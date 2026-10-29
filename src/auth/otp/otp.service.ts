import {
  BadRequestException,
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { CAPTCHA_PROVIDER, type CaptchaProvider } from '../captcha';
import { maskPhone, normalizePhone } from '../phone';
import { parseBody, otpStartSchema, otpVerifySchema } from './otp.schema';
import { ProofTokenService, type ProofPurpose } from './proof-token';
import { OTP_PROVIDER, type OtpProvider } from './otp.provider';

/**
 * Per-IP caps are the only ones that answer 429: everything bound to a phone or
 * a device is silently swallowed so the endpoint cannot be used to probe which
 * numbers are registered or how much budget they have left.
 */
export const OTP_START_IP_LIMIT = { limit: 10, windowSeconds: 600 } as const;
export const OTP_START_PHONE_LIMIT = { limit: 5, windowSeconds: 3600 } as const;
export const OTP_START_DEVICE_LIMIT = { limit: 10, windowSeconds: 3600 } as const;
export const OTP_RESEND_COOLDOWN_SECONDS = 60;
export const OTP_VERIFY_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
export const OTP_VERIFY_PHONE_LIMIT = { limit: 5, windowSeconds: 900 } as const;

/** Fixed tracker for the deployment-wide send cap; it is HMAC'd like any other. */
const GLOBAL_SEND_TRACKER = 'otp-send-global';

export interface OtpRequestContext {
  readonly ip: string;
  readonly deviceKey: string | null;
  readonly requestId: string;
}

export type OtpStartResult =
  | { readonly outcome: 'accepted' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type OtpVerifyResult =
  | { readonly outcome: 'verified'; readonly proof: string }
  | { readonly outcome: 'rejected' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

function hashDeviceKey(deviceKey: string): string {
  // Bounded, non-reversible tracker; the raw header never reaches Redis.
  return createHash('sha256').update(deviceKey, 'utf8').digest('hex');
}

@Injectable()
export class OtpService {
  private readonly globalSendsPerHour: number;

  constructor(
    @Inject(ENV) env: Pick<Env, 'OTP_GLOBAL_SENDS_PER_HOUR'>,
    private readonly rateLimit: RateLimitService,
    private readonly proof: ProofTokenService,
    @Inject(OTP_PROVIDER) private readonly otpProvider: OtpProvider,
    @Inject(CAPTCHA_PROVIDER) private readonly captchaProvider: CaptchaProvider,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.globalSendsPerHour = env.OTP_GLOBAL_SENDS_PER_HOUR;
  }

  /**
   * Always reports success: whether a user exists, whether a code was sent and
   * whether the phone is currently suppressed are indistinguishable to a caller.
   */
  async start(body: unknown, context: OtpRequestContext): Promise<OtpStartResult> {
    const input = parseBody(otpStartSchema, body);

    if (input === null) {
      throw new BadRequestException();
    }

    // Cheapest rejection first: an IP flood must never reach the captcha or Redis.
    const ipDecision = await this.rateLimit.consume({
      scope: 'otp-start-ip',
      identifier: context.ip,
      ...OTP_START_IP_LIMIT,
    });

    if (!ipDecision.allowed) {
      return { outcome: 'throttled', retryAfterSeconds: ipDecision.retryAfterSeconds };
    }

    if (!(await this.verifyCaptcha(input.captchaToken, context.ip))) {
      throw new BadRequestException();
    }

    const phone = normalizePhone(input.phone);

    if (phone === null) {
      // Same generic error as every other start failure: no format hints.
      throw new BadRequestException();
    }

    const phoneE164 = phone.e164;

    const globalDecision = await this.rateLimit.consume({
      scope: 'otp-start-global',
      identifier: GLOBAL_SEND_TRACKER,
      limit: this.globalSendsPerHour,
      windowSeconds: 3600,
    });

    if (!globalDecision.allowed) {
      return { outcome: 'throttled', retryAfterSeconds: globalDecision.retryAfterSeconds };
    }

    if (!(await this.maySend(phoneE164, context.deviceKey))) {
      return { outcome: 'accepted' };
    }

    try {
      // The purpose travels with the challenge so a later verify can bind the
      // proof to the action the code was requested for.
      await this.otpProvider.start(phoneE164, { purpose: input.purpose });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, phone: maskPhone(phoneE164) },
        'otp send failed',
      );
      throw new ServiceUnavailableException();
    }

    this.logger.info({ requestId: context.requestId, phone: maskPhone(phoneE164) }, 'otp sent');

    return { outcome: 'accepted' };
  }

  /** Every rejection here is indistinguishable from a wrong code. */
  async verify(body: unknown, context: OtpRequestContext): Promise<OtpVerifyResult> {
    const input = parseBody(otpVerifySchema, body);

    if (input === null) {
      return { outcome: 'rejected' };
    }

    const ipDecision = await this.rateLimit.consume({
      scope: 'otp-verify-ip',
      identifier: context.ip,
      ...OTP_VERIFY_IP_LIMIT,
    });

    if (!ipDecision.allowed) {
      return { outcome: 'throttled', retryAfterSeconds: ipDecision.retryAfterSeconds };
    }

    const phone = normalizePhone(input.phone);

    if (phone === null) {
      return { outcome: 'rejected' };
    }

    const phoneE164 = phone.e164;

    const attempts = await this.rateLimit.consume({
      scope: 'otp-verify-phone',
      identifier: phoneE164,
      ...OTP_VERIFY_PHONE_LIMIT,
    });

    if (!attempts.allowed) {
      await this.recordLockoutOnce(phoneE164, context);
      return { outcome: 'rejected' };
    }

    if (!(await this.checkCode(phoneE164, input.code))) {
      return { outcome: 'rejected' };
    }

    // A successful check clears the wrong-try budget for this phone.
    await this.rateLimit.reset({ scope: 'otp-verify-phone', identifier: phoneE164 });

    const proof = await this.proof.issue(phoneE164, input.purpose);

    await this.recordVerified(phoneE164, context);

    this.logger.info({ requestId: context.requestId, phone: maskPhone(phoneE164) }, 'otp verified');

    return { outcome: 'verified', proof };
  }

  /**
   * Sends a code for a purpose the server chose itself.
   *
   * Only the authenticated phone-change flow calls this. The public endpoints
   * take their purpose from a request body and narrow it to `PUBLIC_OTP_PURPOSES`,
   * so no caller can mint a phone-change proof from outside. The deployment-wide
   * send cap applies here too; the caller owns its own per-user budgets.
   */
  async sendPurposeCode(
    phoneE164: string,
    purpose: ProofPurpose,
    context: OtpRequestContext,
  ): Promise<OtpStartResult> {
    const globalDecision = await this.rateLimit.consume({
      scope: 'otp-start-global',
      identifier: GLOBAL_SEND_TRACKER,
      limit: this.globalSendsPerHour,
      windowSeconds: 3600,
    });

    if (!globalDecision.allowed) {
      return { outcome: 'throttled', retryAfterSeconds: globalDecision.retryAfterSeconds };
    }

    try {
      await this.otpProvider.start(phoneE164, { purpose });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, phone: maskPhone(phoneE164) },
        'otp send failed',
      );
      throw new ServiceUnavailableException();
    }

    this.logger.info({ requestId: context.requestId, phone: maskPhone(phoneE164) }, 'otp sent');

    return { outcome: 'accepted' };
  }

  /**
   * Checks a code against a purpose the server chose and mints the proof for
   * it. Null means "wrong code": the attempt budgets belong to the caller, so
   * a mismatch here carries no lockout of its own.
   */
  async verifyPurposeCode(
    phoneE164: string,
    code: string,
    purpose: ProofPurpose,
    context: OtpRequestContext,
  ): Promise<string | null> {
    if (!(await this.checkCode(phoneE164, code))) {
      return null;
    }

    const proof = await this.proof.issue(phoneE164, purpose);

    await this.recordVerified(phoneE164, context);

    this.logger.info({ requestId: context.requestId, phone: maskPhone(phoneE164) }, 'otp verified');

    return proof;
  }

  /** Phone caps, device cap and the resend cooldown: a hit means "pretend we sent it". */
  private async maySend(phoneE164: string, deviceKey: string | null): Promise<boolean> {
    const cooldown = await this.rateLimit.consume({
      scope: 'otp-start-cooldown',
      identifier: phoneE164,
      limit: 1,
      windowSeconds: OTP_RESEND_COOLDOWN_SECONDS,
    });

    if (!cooldown.allowed) {
      return false;
    }

    const perPhone = await this.rateLimit.consume({
      scope: 'otp-start-phone',
      identifier: phoneE164,
      ...OTP_START_PHONE_LIMIT,
    });

    if (!perPhone.allowed) {
      return false;
    }

    if (deviceKey === null) {
      return true;
    }

    const perDevice = await this.rateLimit.consume({
      scope: 'otp-start-device',
      identifier: hashDeviceKey(deviceKey),
      ...OTP_START_DEVICE_LIMIT,
    });

    return perDevice.allowed;
  }

  private async verifyCaptcha(token: string, ip: string): Promise<boolean> {
    try {
      return await this.captchaProvider.verify(token, ip);
    } catch {
      // A broken captcha provider must not turn into a bypass.
      return false;
    }
  }

  private async checkCode(phoneE164: string, code: string): Promise<boolean> {
    try {
      // Fake providers check the code themselves; a provider returning a
      // challengeRef needs per-send storage, which is not wired up yet.
      return await this.otpProvider.check(phoneE164, code, null);
    } catch {
      throw new ServiceUnavailableException();
    }
  }

  /** One audit row per 15-minute lockout, not one per refused attempt. */
  private async recordLockoutOnce(phoneE164: string, context: OtpRequestContext): Promise<void> {
    const notice = await this.rateLimit.consume({
      scope: 'otp-verify-lock-notice',
      identifier: phoneE164,
      limit: 1,
      windowSeconds: OTP_VERIFY_PHONE_LIMIT.windowSeconds,
    });

    if (!notice.allowed) {
      return;
    }

    await this.writeAudit('otp.locked', phoneE164, context, false);
  }

  private async recordVerified(phoneE164: string, context: OtpRequestContext): Promise<void> {
    await this.writeAudit('otp.verified', phoneE164, context, true);
  }

  /**
   * Details carry the masked phone only; the IP is hashed by `AuditService`.
   * A lockout audit is best effort, a success audit is not.
   */
  private async writeAudit(
    action: string,
    phoneE164: string,
    context: OtpRequestContext,
    required: boolean,
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorRole: 'system',
        targetType: 'phone',
        requestId: context.requestId,
        ip: context.ip,
        metadata: { actor: 'system', phone: maskPhone(phoneE164) },
      });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, phone: maskPhone(phoneE164) },
        'otp audit failed',
      );

      if (required) {
        throw new ServiceUnavailableException();
      }
    }
  }
}
