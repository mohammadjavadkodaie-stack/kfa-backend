import { BadRequestException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import type { AuthRequestContext, SessionPrincipal } from '../auth.service';
import { CAPTCHA_PROVIDER, type CaptchaProvider } from '../captcha';
import { parseBody } from '../otp/otp.schema';
import { OTP_PROVIDER, type OtpProvider } from '../otp/otp.provider';
import { OtpService } from '../otp/otp.service';
import { ProofTokenService } from '../otp/proof-token';
import { maskPhone, normalizePhone } from '../phone';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';
import {
  phoneChangeConfirmSchema,
  phoneChangeStartSchema,
  phoneChangeVerifyNewSchema,
  phoneChangeVerifyOldSchema,
} from './phone-change.schema';

/**
 * Two codes and one swap.
 *
 * A signed-in user moves the account to a number they have to prove, and the
 * number that loses the account is told about it. The current number never
 * comes from a request and the purposes are picked by this service, so a
 * `phone_change_*` proof can only exist because this flow minted one.
 */

export const PHONE_CHANGE_START_IP_LIMIT = { limit: 5, windowSeconds: 900 } as const;
export const PHONE_CHANGE_START_USER_LIMIT = { limit: 5, windowSeconds: 3_600 } as const;
export const PHONE_CHANGE_START_DEVICE_LIMIT = { limit: 10, windowSeconds: 3_600 } as const;
export const PHONE_CHANGE_START_COOLDOWN_SECONDS = 60;
export const PHONE_CHANGE_VERIFY_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
export const PHONE_CHANGE_VERIFY_USER_LIMIT = { limit: 10, windowSeconds: 900 } as const;
export const PHONE_CHANGE_CONFIRM_IP_LIMIT = { limit: 10, windowSeconds: 900 } as const;
export const PHONE_CHANGE_CONFIRM_USER_LIMIT = { limit: 5, windowSeconds: 900 } as const;

/** Bounded, non-reversible tracker: the raw device key never reaches Redis. */
function deviceTracker(deviceKey: string): string {
  return createHash('sha256').update(deviceKey, 'utf8').digest('hex');
}

export type PhoneChangeStartResult =
  | { readonly outcome: 'accepted' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type PhoneChangeVerifyResult =
  | { readonly outcome: 'verified'; readonly proof: string }
  /** Wrong, expired or reused code: the caller cannot tell which. */
  | { readonly outcome: 'rejected' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type PhoneChangeConfirmResult =
  | { readonly outcome: 'changed' }
  /** One rejection for invalid, expired, reused, mismatched and conflicting. */
  | { readonly outcome: 'rejected' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

@Injectable()
export class PhoneChangeService {
  constructor(
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    private readonly proof: ProofTokenService,
    private readonly otp: OtpService,
    @Inject(OTP_PROVIDER) private readonly otpProvider: OtpProvider,
    @Inject(CAPTCHA_PROVIDER) private readonly captchaProvider: CaptchaProvider,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * One code to the new number, one to the number on the account.
   *
   * A number that already belongs to somebody else gets no code, but the answer
   * is the same as for a free number: the endpoint cannot be used to ask
   * whether a number is registered.
   */
  async start(
    principal: SessionPrincipal,
    body: unknown,
    context: AuthRequestContext,
  ): Promise<PhoneChangeStartResult> {
    const ipThrottle = await this.enforceLimit(
      'phone-change-start-ip',
      context.ip,
      PHONE_CHANGE_START_IP_LIMIT,
    );

    if (ipThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: ipThrottle };
    }

    const input = parseBody(phoneChangeStartSchema, body);

    if (input === null) throw new BadRequestException();

    if (!(await this.verifyCaptcha(input.captchaToken, context.ip))) {
      throw new BadRequestException();
    }

    const phone = normalizePhone(input.phone);

    if (phone === null) throw new BadRequestException();

    const newPhone = phone.e164;

    const userThrottle = await this.enforceLimit(
      'phone-change-start-user',
      principal.userId,
      PHONE_CHANGE_START_USER_LIMIT,
    );

    if (userThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: userThrottle };
    }

    // Two SMS per start: a user who taps twice gets one code, not four.
    const cooldown = await this.enforceLimit('phone-change-start-cooldown', principal.userId, {
      limit: 1,
      windowSeconds: PHONE_CHANGE_START_COOLDOWN_SECONDS,
    });

    if (cooldown !== null) {
      return { outcome: 'throttled', retryAfterSeconds: cooldown };
    }

    if (!(await this.underDeviceBudget(context.deviceKey))) {
      // Same shape as a real send: a device over its budget learns nothing.
      return { outcome: 'accepted' };
    }

    const currentPhone = await this.sessions.findPhoneByUserId(principal.userId);

    if (currentPhone === null) throw new UnauthorizedException();

    if (currentPhone === newPhone) throw new BadRequestException();

    const taken = (await this.sessions.findUserByPhone(newPhone)) !== null;

    const toOld = await this.otp.sendPurposeCode(currentPhone, 'phone_change_old', context);

    if (toOld.outcome === 'throttled') {
      return { outcome: 'throttled', retryAfterSeconds: toOld.retryAfterSeconds };
    }

    if (!taken) {
      const toNew = await this.otp.sendPurposeCode(newPhone, 'phone_change_new', context);

      if (toNew.outcome === 'throttled') {
        return { outcome: 'throttled', retryAfterSeconds: toNew.retryAfterSeconds };
      }
    }

    await this.writeAudit('auth.phone_change.started', principal.userId, currentPhone, context, {
      newPhone: maskPhone(newPhone),
      newPhoneTaken: taken,
    });

    this.logger.info(
      { requestId: context.requestId, userId: principal.userId, phone: maskPhone(currentPhone) },
      'phone change started',
    );

    return { outcome: 'accepted' };
  }

  /** Checks the code sent to the new number and mints its single-use proof. */
  async verifyNew(
    principal: SessionPrincipal,
    body: unknown,
    context: AuthRequestContext,
  ): Promise<PhoneChangeVerifyResult> {
    const ipThrottle = await this.enforceLimit(
      'phone-change-verify-ip',
      context.ip,
      PHONE_CHANGE_VERIFY_IP_LIMIT,
    );

    if (ipThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: ipThrottle };
    }

    const input = parseBody(phoneChangeVerifyNewSchema, body);

    if (input === null) return { outcome: 'rejected' };

    const userThrottle = await this.enforceLimit(
      'phone-change-verify-user',
      principal.userId,
      PHONE_CHANGE_VERIFY_USER_LIMIT,
    );

    if (userThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: userThrottle };
    }

    const phone = normalizePhone(input.phone);

    if (phone === null) return { outcome: 'rejected' };

    const proof = await this.otp.verifyPurposeCode(
      phone.e164,
      input.code,
      'phone_change_new',
      context,
    );

    if (proof === null) {
      this.logger.warn(
        { requestId: context.requestId, userId: principal.userId, phone: maskPhone(phone.e164) },
        'phone change code rejected',
      );

      return { outcome: 'rejected' };
    }

    return { outcome: 'verified', proof };
  }

  /**
   * Checks the code sent to the number on the account. That number is read from
   * the database, so a body cannot point this step at somebody else's phone.
   */
  async verifyOld(
    principal: SessionPrincipal,
    body: unknown,
    context: AuthRequestContext,
  ): Promise<PhoneChangeVerifyResult> {
    const ipThrottle = await this.enforceLimit(
      'phone-change-verify-ip',
      context.ip,
      PHONE_CHANGE_VERIFY_IP_LIMIT,
    );

    if (ipThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: ipThrottle };
    }

    const input = parseBody(phoneChangeVerifyOldSchema, body);

    if (input === null) return { outcome: 'rejected' };

    const userThrottle = await this.enforceLimit(
      'phone-change-verify-user',
      principal.userId,
      PHONE_CHANGE_VERIFY_USER_LIMIT,
    );

    if (userThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: userThrottle };
    }

    const currentPhone = await this.sessions.findPhoneByUserId(principal.userId);

    if (currentPhone === null) throw new UnauthorizedException();

    const proof = await this.otp.verifyPurposeCode(
      currentPhone,
      input.code,
      'phone_change_old',
      context,
    );

    if (proof === null) {
      this.logger.warn(
        { requestId: context.requestId, userId: principal.userId, phone: maskPhone(currentPhone) },
        'phone change code rejected',
      );

      return { outcome: 'rejected' };
    }

    return { outcome: 'verified', proof };
  }

  /**
   * Spends both proofs, writes the new number and locks out every other session.
   *
   * The old proof is matched against the number on the account before the new
   * proof is spent, so a stale "old" proof leaves the new one usable. Every
   * failure below - missing, expired, reused, cross-purpose, foreign phone or a
   * number that got taken in the meantime - answers the same `rejected`.
   */
  async confirm(
    principal: SessionPrincipal,
    body: unknown,
    context: AuthRequestContext,
  ): Promise<PhoneChangeConfirmResult> {
    const ipThrottle = await this.enforceLimit(
      'phone-change-confirm-ip',
      context.ip,
      PHONE_CHANGE_CONFIRM_IP_LIMIT,
    );

    if (ipThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: ipThrottle };
    }

    const input = parseBody(phoneChangeConfirmSchema, body);

    if (input === null) return { outcome: 'rejected' };

    const userThrottle = await this.enforceLimit(
      'phone-change-confirm-user',
      principal.userId,
      PHONE_CHANGE_CONFIRM_USER_LIMIT,
    );

    if (userThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: userThrottle };
    }

    const currentPhone = await this.sessions.findPhoneByUserId(principal.userId);

    if (currentPhone === null) throw new UnauthorizedException();

    const provedOldPhone = await this.proof.verifyAndConsumeProof(
      input.proofOld,
      'phone_change_old',
    );

    if (provedOldPhone === null || provedOldPhone !== currentPhone) {
      return { outcome: 'rejected' };
    }

    const newPhone = await this.proof.verifyAndConsumeProof(input.proofNew, 'phone_change_new');

    if (newPhone === null || newPhone === currentPhone) {
      return { outcome: 'rejected' };
    }

    const changed = await this.sessions.changePhone({
      userId: principal.userId,
      phone: newPhone,
      // The session that asked for the change is the one that keeps working.
      keepSessionId: principal.sessionId,
      now: new Date(),
    });

    if (changed.outcome !== 'changed') return { outcome: 'rejected' };

    await this.writeAudit('auth.phone_changed', principal.userId, currentPhone, context, {
      newPhone: maskPhone(newPhone),
      sessionsRevoked: changed.revokedSessions,
    });

    this.logger.info(
      { requestId: context.requestId, userId: principal.userId, phone: maskPhone(newPhone) },
      'phone changed',
    );

    await this.sendNotice(currentPhone, newPhone, principal.userId, context);

    return { outcome: 'changed' };
  }

  /**
   * Tells the number that just lost the account, after the change is committed.
   *
   * Best effort on purpose: the codes are spent and the number is written, so a
   * dead gateway must not turn a successful change into an error. The failure is
   * still recorded, and the message only ever names the masked new number.
   */
  private async sendNotice(
    oldPhone: string,
    newPhone: string,
    userId: string,
    context: AuthRequestContext,
  ): Promise<void> {
    try {
      await this.otpProvider.notify(oldPhone, {
        kind: 'phone_changed',
        maskedPhone: maskPhone(newPhone),
      });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, userId, phone: maskPhone(oldPhone) },
        'phone change notice failed',
      );

      await this.writeAudit('auth.phone_change.notice_failed', userId, oldPhone, context, {});
    }
  }

  /** Returns the retry hint when the budget is exhausted, or null when allowed. */
  private async enforceLimit(
    scope: string,
    identifier: string,
    limit: { limit: number; windowSeconds: number },
  ): Promise<number | null> {
    const decision = await this.rateLimit.consume({ scope, identifier, ...limit });

    return decision.allowed ? null : decision.retryAfterSeconds;
  }

  /** A keyless client has no device budget to spend. */
  private async underDeviceBudget(deviceKey: string | null): Promise<boolean> {
    if (deviceKey === null) return true;

    const decision = await this.rateLimit.consume({
      scope: 'phone-change-start-device',
      identifier: deviceTracker(deviceKey),
      ...PHONE_CHANGE_START_DEVICE_LIMIT,
    });

    return decision.allowed;
  }

  private async verifyCaptcha(token: string, ip: string): Promise<boolean> {
    try {
      return await this.captchaProvider.verify(token, ip);
    } catch {
      // A broken captcha provider must not turn into a bypass.
      return false;
    }
  }

  /**
   * Best effort, like the OTP trail: the change itself is the record, and an
   * audit outage must not roll back a number that the user already proved.
   */
  private async writeAudit(
    action: string,
    actorId: string,
    phoneE164: string | null,
    context: AuthRequestContext,
    extra: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorId,
        actorRole: 'user',
        targetType: 'user',
        targetId: actorId,
        requestId: context.requestId,
        ip: context.ip,
        metadata: {
          actor: 'user',
          ...(phoneE164 === null ? {} : { phone: maskPhone(phoneE164) }),
          ...extra,
        },
      });
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'phone change audit failed');
    }
  }
}
