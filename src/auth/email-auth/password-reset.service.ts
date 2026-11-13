import {
  BadRequestException,
  HttpException,
  Inject,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { EmailCodeService } from '../email/email-code.service';
import { EmailProofService } from '../email/email-proof';
import { EMAIL_PROVIDER, type EmailProvider } from '../email/email.provider';
import { maskEmail, normalizeEmail } from '../email/email';
import { validatePassword } from '../password/password.policy';
import { PasswordBusyError, PasswordService } from '../password/password.service';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';

/** A reset is a single write, so the budget only has to stop scripted abuse. */
export const PASSWORD_RESET_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
/** Recorded on every successful reset; the reason also lands on each session row. */
export const PASSWORD_RESET_AUDIT_ACTION = 'password.reset';
export const PASSWORD_RESET_REVOCATION_REASON = 'password_reset';

interface ResetContext {
  readonly ip: string;
  readonly requestId: string;
}

/** One answer for "no such proof" and "that proof is spent": nothing to learn. */
function invalidProof(): UnauthorizedException {
  return new UnauthorizedException({ error: 'invalid_proof' });
}

/**
 * "I forgot my password", in two steps.
 *
 * Both steps are unauthenticated by design, so neither may become an account
 * oracle: the start step answers exactly like the register start (a code is
 * mailed only when the address has a password to reset), and the finish step
 * answers every proof failure with the same 401.
 *
 * The proof is read twice on purpose. The first, non-consuming read lets a
 * weak password be refused without spending the code the user just typed; the
 * second read is the one that takes the nonce, immediately before the hash is
 * written. A proof that disappears in between is a replay attempt and ends in
 * the same 401.
 */
@Injectable()
export class PasswordResetService {
  constructor(
    private readonly emailCode: EmailCodeService,
    private readonly proof: EmailProofService,
    private readonly password: PasswordService,
    private readonly rateLimit: RateLimitService,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    @Inject(EMAIL_PROVIDER) private readonly email: EmailProvider,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * Mails a reset code, or silently does nothing.
   *
   * The limiter, captcha and cooldown work runs either way, so an unknown
   * address costs exactly what a known one costs; only the send is skipped.
   */
  async start(input: {
    readonly email: string;
    readonly captchaToken: string;
    readonly ip: string;
    readonly deviceKey?: string | null;
  }): Promise<void> {
    const email = normalizeEmail(input.email);
    if (email === null) throw new BadRequestException();

    const account = await this.sessions.findUserByEmail(email);

    await this.emailCode.start({
      email,
      purpose: 'password_reset',
      captchaToken: input.captchaToken,
      ip: input.ip,
      deviceKey: input.deviceKey,
      // Nothing to reset when there is no account or no password on it.
      eligible: account !== null && account.passwordHash !== null,
    });
  }

  /**
   * Spends the proof on a new password.
   *
   * Order matters: policy first (so a rejected password leaves the proof
   * usable), then the single use, then the write. Every session is revoked and
   * no credentials are issued - the user signs in again with the new password.
   */
  async reset(input: {
    readonly proof: unknown;
    readonly newPassword: string;
    readonly ip: string;
    readonly requestId: string;
  }): Promise<void> {
    const throttle = await this.rateLimit.consume({
      scope: 'password-reset-ip',
      identifier: input.ip,
      ...PASSWORD_RESET_IP_LIMIT,
    });
    if (!throttle.allowed) {
      throw new HttpException(
        { error: 'rate_limited', retryAfterSeconds: throttle.retryAfterSeconds },
        429,
      );
    }

    const email = await this.proof.peekEmailProof({
      proof: input.proof,
      purpose: 'password_reset',
    });
    if (email === null) throw invalidProof();

    const account = await this.sessions.findUserByEmail(email);
    if (account === null || account.passwordHash === null) throw invalidProof();

    const policy = validatePassword(input.newPassword, { email, username: account.username });
    if (!policy.ok) {
      throw new BadRequestException({ error: 'weak_password', reason: policy.reason });
    }

    let passwordHash: string;
    try {
      passwordHash = await this.password.hash(input.newPassword);
    } catch (error) {
      // Capacity, not credentials: keep the 503 so the proof can be retried.
      if (error instanceof PasswordBusyError) throw new ServiceUnavailableException();
      throw error;
    }

    const proved = await this.proof.consumeEmailProof({
      proof: input.proof,
      purpose: 'password_reset',
    });
    if (proved !== email) throw invalidProof();

    await this.sessions.updatePasswordHash(account.id, passwordHash);
    // A stolen cookie must not survive the reset it was not part of.
    await this.sessions.revokeAllUserSessions(
      account.id,
      PASSWORD_RESET_REVOCATION_REASON,
      new Date(),
    );

    await this.sendNotice(email, account.id, input);
    await this.writeAudit(account.id, email, input);

    this.logger.info({ requestId: input.requestId, userId: account.id }, 'password reset');
  }

  /**
   * Tells the owner that the password changed, after the change is committed.
   *
   * Best effort on purpose: a dead mail gateway must not turn a reset the user
   * already completed into an error, and the message carries no code and no
   * password - just the fact of the change.
   */
  private async sendNotice(email: string, userId: string, context: ResetContext): Promise<void> {
    try {
      await this.email.sendNotice({ to: email, kind: 'password_changed' });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, userId, email: maskEmail(email) },
        'password reset notice failed',
      );
    }
  }

  /**
   * Best effort for the same reason: the password is already written. The email
   * is masked, and no proof, code or password ever reaches the metadata.
   */
  private async writeAudit(userId: string, email: string, context: ResetContext): Promise<void> {
    try {
      await this.audit.record({
        action: PASSWORD_RESET_AUDIT_ACTION,
        actorId: userId,
        actorRole: 'user',
        targetType: 'user',
        targetId: userId,
        requestId: context.requestId,
        ip: context.ip,
        metadata: { actor: 'user', email: maskEmail(email) },
      });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, action: PASSWORD_RESET_AUDIT_ACTION },
        'password reset audit failed',
      );
    }
  }
}
