import { ConflictException, Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { ENV } from '../../config/config.module';
import { TOTP_ENC_KEY_BYTES, type Env } from '../../config/env';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { generateRecoveryCodes, hashRecoveryCode, normalizeRecoveryCode } from './recovery-codes';
import { base32Encode, buildOtpauthUri, generateTotpSecret, verifyTotp } from './totp';
import { TOTP_REPOSITORY, type TotpRepository } from './totp.repository';
import { TOTP_ROTATION_STORE, type TotpRotationStore } from './totp-rotation.store';
import { decryptTotpSecret, encryptTotpSecret } from './totp-secret-box';

/**
 * Wrong codes, replays and lockouts all look the same to a caller, so a stolen
 * session cannot use this service to probe the second factor of an account.
 */
export const TOTP_VERIFY_USER_LIMIT = { limit: 5, windowSeconds: 900 } as const;

/** Codes shown once at confirmation, then stored as hashes only. */
const RECOVERY_CODE_COUNT = 10;

const ISSUER = 'KFA';
const TOTP_CODE_PATTERN = /^[0-9]{6}$/;

const VERIFY_SCOPE = 'totp-verify-user';
const LOCK_NOTICE_SCOPE = 'totp-lock-notice';

export interface EnrollmentStart {
  /** Leaves this object exactly once, inside the enrollment response. */
  readonly secretBase32: string;
  readonly otpauthUri: string;
}

export type EnrollmentConfirmation =
  | { readonly outcome: 'confirmed'; readonly recoveryCodes: string[] }
  /** No pending enrollment, a wrong code, a replay or a lockout: one answer. */
  | { readonly outcome: 'rejected' };

export type TotpVerification =
  { readonly ok: true; readonly method: 'totp' | 'recovery' } | { readonly ok: false };

/** Same one-answer rule as enrollment: no pending, wrong, stale or locked out. */
export type RotationConfirmation =
  | { readonly outcome: 'rotated'; readonly recoveryCodes: string[] }
  | { readonly outcome: 'rejected' };

/** What the client may know about its own factor. No secret, no hash. */
export interface TotpStatus {
  readonly confirmed: boolean;
  readonly recoveryCodesLeft: number;
}

/** Absent or malformed key material means TOTP is off, not "allow everything". */
function decodeKey(value: string | undefined): Buffer | null {
  if (value === undefined) return null;

  const key = Buffer.from(value, 'base64url');

  return key.length === TOTP_ENC_KEY_BYTES ? key : null;
}

function notConfigured(): ServiceUnavailableException {
  // Generic on purpose: the caller learns nothing about the key or the reason.
  return new ServiceUnavailableException();
}

@Injectable()
export class TotpService {
  private readonly encKey: Buffer | null;

  constructor(
    @Inject(ENV) env: Pick<Env, 'TOTP_ENC_KEY'>,
    @Inject(TOTP_REPOSITORY) private readonly repository: TotpRepository,
    @Inject(TOTP_ROTATION_STORE) private readonly rotations: TotpRotationStore,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.encKey = decodeKey(env.TOTP_ENC_KEY);
  }

  /**
   * Read-only view of the caller's own factor. Needs no key: nothing here is
   * decrypted, and an unconfirmed enrollment simply has no recovery codes.
   */
  async getStatus(userId: string): Promise<TotpStatus> {
    const credential = await this.repository.getCredential(userId);
    const confirmed = credential !== null && credential.confirmedAt !== null;

    return {
      confirmed,
      recoveryCodesLeft: confirmed ? await this.repository.countUnusedRecoveryCodes(userId) : 0,
    };
  }

  /**
   * Starts (or restarts) an unconfirmed enrollment.
   *
   * Role checks (ADMIN/OWNER only) belong to the endpoints in stage 3.2c; this
   * service is always called with an already authenticated user id.
   */
  async startEnrollment(userId: string, label: string): Promise<EnrollmentStart> {
    const key = this.requireKey();
    const secret = generateTotpSecret();
    const saved = await this.repository.saveUnconfirmed(
      userId,
      encryptTotpSecret(secret, key, userId),
    );

    if (!saved) {
      // Same refusal whether the user is enrolled or lost a concurrent race.
      throw new ConflictException();
    }

    const secretBase32 = base32Encode(secret);

    return {
      secretBase32,
      otpauthUri: buildOtpauthUri({ issuer: ISSUER, label, secretBase32 }),
    };
  }

  /** Returns the recovery codes once; a wrong code only spends attempt budget. */
  async confirmEnrollment(
    userId: string,
    code: string,
    nowMs: number,
  ): Promise<EnrollmentConfirmation> {
    const key = this.requireKey();

    if (!(await this.beginAttempt(userId))) return { outcome: 'rejected' };

    const credential = await this.repository.getCredential(userId);

    if (credential === null || credential.confirmedAt !== null) {
      // Nothing pending: the same answer as a wrong code.
      return { outcome: 'rejected' };
    }

    const step = this.matchCode(credential.secretEnc, key, userId, code, nowMs);

    if (step === null) return { outcome: 'rejected' };

    const recoveryCodes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    const codeHashes = recoveryCodes.map((recoveryCode) => hashRecoveryCode(recoveryCode, key));

    await this.rateLimit.reset({ scope: VERIFY_SCOPE, identifier: userId });

    if (!(await this.repository.confirm(userId, step, codeHashes))) {
      return { outcome: 'rejected' };
    }

    await this.writeAudit(userId, 'totp.enrolled', {
      recoveryCodesIssued: recoveryCodes.length,
    });

    return { outcome: 'confirmed', recoveryCodes };
  }

  /**
   * Starts a replacement for an already confirmed factor.
   *
   * The pending ciphertext is held outside the credential row, so the current
   * authenticator keeps working until the replacement is proven. A second start
   * simply replaces the older pending one. No confirmed credential means there
   * is nothing to rotate, which answers like a second enrollment.
   */
  async startRotation(userId: string, label: string): Promise<EnrollmentStart> {
    const key = this.requireKey();
    const active = await this.repository.getCredential(userId);

    if (active === null || active.confirmedAt === null) throw new ConflictException();

    const secret = generateTotpSecret();
    const secretEnc = encryptTotpSecret(secret, key, userId);

    await this.rotations.save(userId, { secretEnc, expectedSecretEnc: active.secretEnc });

    const secretBase32 = base32Encode(secret);

    return {
      secretBase32,
      otpauthUri: buildOtpauthUri({ issuer: ISSUER, label, secretBase32 }),
    };
  }

  /**
   * Proves the pending replacement, then swaps it in with fresh recovery codes.
   *
   * A wrong code spends the same per-user attempt budget as a step-up and never
   * reaches the repository, so the active factor and its codes stay untouched.
   * The swap itself is one repository transaction bound to the old ciphertext.
   */
  async confirmRotation(
    userId: string,
    code: string,
    nowMs: number,
  ): Promise<RotationConfirmation> {
    const key = this.requireKey();

    if (!(await this.beginAttempt(userId))) return { outcome: 'rejected' };

    const pending = await this.rotations.read(userId);

    if (pending === null) return { outcome: 'rejected' };

    const active = await this.repository.getCredential(userId);

    // A reset or another swap since the start invalidates the replacement.
    if (
      active === null ||
      active.confirmedAt === null ||
      active.secretEnc !== pending.expectedSecretEnc
    ) {
      return { outcome: 'rejected' };
    }

    const step = this.matchCode(pending.secretEnc, key, userId, code, nowMs);

    if (step === null) return { outcome: 'rejected' };

    const recoveryCodes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    const codeHashes = recoveryCodes.map((recoveryCode) => hashRecoveryCode(recoveryCode, key));

    if (
      !(await this.repository.rotate(
        userId,
        pending.expectedSecretEnc,
        pending.secretEnc,
        step,
        codeHashes,
      ))
    ) {
      return { outcome: 'rejected' };
    }

    // The swap already invalidated the pending value; clearing keeps it tidy.
    await this.rotations.clear(userId);
    await this.rateLimit.reset({ scope: VERIFY_SCOPE, identifier: userId });

    return { outcome: 'rotated', recoveryCodes };
  }

  /**
   * One answer for every failure: no credential, unconfirmed, wrong, replayed,
   * locked or malformed. Only a rate-limit outage surfaces as an error.
   */
  async verifyCode(userId: string, input: unknown, nowMs: number): Promise<TotpVerification> {
    const key = this.requireKey();

    // Lock check first: a locked user must not cost a decryption.
    if (!(await this.beginAttempt(userId))) return { ok: false };

    const credential = await this.repository.getCredential(userId);

    if (credential === null || credential.confirmedAt === null) return { ok: false };

    if (typeof input === 'string' && TOTP_CODE_PATTERN.test(input)) {
      const step = this.matchCode(credential.secretEnc, key, userId, input, nowMs);

      if (step === null) return { ok: false };

      // The update is the replay decision: the same or an older step loses.
      if (!(await this.repository.advanceStep(userId, step))) return { ok: false };

      await this.rateLimit.reset({ scope: VERIFY_SCOPE, identifier: userId });

      return { ok: true, method: 'totp' };
    }

    const normalized = normalizeRecoveryCode(input);

    if (normalized === null) return { ok: false };

    if (!(await this.repository.consumeRecoveryCode(userId, hashRecoveryCode(normalized, key)))) {
      return { ok: false };
    }

    await this.rateLimit.reset({ scope: VERIFY_SCOPE, identifier: userId });

    const remaining = await this.repository.countUnusedRecoveryCodes(userId);

    await this.writeAudit(userId, 'totp.recovery_used', { remainingRecoveryCodes: remaining });

    return { ok: true, method: 'recovery' };
  }

  private requireKey(): Buffer {
    if (this.encKey === null) throw notConfigured();

    return this.encKey;
  }

  /**
   * Bills one attempt against the per-user budget and runs before any crypto.
   * False means the user is locked out, even with a correct code.
   */
  private async beginAttempt(userId: string): Promise<boolean> {
    const decision = await this.rateLimit.consume({
      scope: VERIFY_SCOPE,
      identifier: userId,
      ...TOTP_VERIFY_USER_LIMIT,
    });

    if (decision.allowed) return true;

    await this.recordLockoutOnce(userId);

    return false;
  }

  /** Decryption failures (wrong key, moved ciphertext, torn row) are "wrong code". */
  private matchCode(
    secretEnc: string,
    key: Buffer,
    userId: string,
    code: string,
    nowMs: number,
  ): number | null {
    try {
      return verifyTotp(decryptTotpSecret(secretEnc, key, userId), code, nowMs);
    } catch {
      return null;
    }
  }

  /** One audit row per lock window, not one per refused attempt. */
  private async recordLockoutOnce(userId: string): Promise<void> {
    const notice = await this.rateLimit.consume({
      scope: LOCK_NOTICE_SCOPE,
      identifier: userId,
      limit: 1,
      windowSeconds: TOTP_VERIFY_USER_LIMIT.windowSeconds,
    });

    if (!notice.allowed) return;

    await this.writeAudit(userId, 'totp.locked', {
      windowSeconds: TOTP_VERIFY_USER_LIMIT.windowSeconds,
    });
  }

  /**
   * Details never carry a code, a secret, a recovery code, a hash or the
   * ciphertext. Best effort: an audit outage must not undo a stored factor.
   */
  private async writeAudit(
    userId: string,
    action: string,
    metadata: Record<string, number>,
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorId: userId,
        targetType: 'user',
        targetId: userId,
        metadata,
      });
    } catch {
      this.logger.warn({ userId, action }, 'totp audit failed');
    }
  }
}
