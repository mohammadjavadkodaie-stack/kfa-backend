import {
  BadRequestException,
  HttpException,
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash, randomInt } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { CAPTCHA_PROVIDER, type CaptchaProvider } from '../captcha/captcha.provider';
import { isDisposableEmailDomain, maskEmail, normalizeEmail } from './email';
import { deriveEmailCodeKey, EmailCodeKeyMissingError } from './email-keys';
import { emailCodeKey, hashEmailCode } from './email-code.hash';
import {
  EMAIL_CODE_STORE,
  EmailCodeStoreUnavailableError,
  type EmailCodeStore,
} from './email-code.store';
import { EMAIL_PROVIDER, type EmailCodePurpose, type EmailProvider } from './email.provider';
import { EmailProofService } from './email-proof';

export const EMAIL_START_IP_LIMIT = { limit: 10, windowSeconds: 600 } as const;
export const EMAIL_START_EMAIL_LIMIT = { limit: 5, windowSeconds: 3600 } as const;
export const EMAIL_START_DEVICE_LIMIT = { limit: 5, windowSeconds: 3600 } as const;
export const EMAIL_RESEND_COOLDOWN_SECONDS = 60;
export const EMAIL_VERIFY_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
const GLOBAL_SEND_TRACKER = 'email-send-global';
export const EMAIL_CODE_AUDIT_ACTIONS = {
  VERIFIED: 'email_code.verified',
  LOCKED: 'email_code.locked',
} as const;
const EMAIL_PURPOSES: ReadonlySet<EmailCodePurpose> = new Set([
  'register',
  'login_device',
  'password_reset',
  'email_change_new',
  'email_change_old',
]);
const CODE_PATTERN = /^[0-9]{6}$/u;

export interface EmailStartInput {
  readonly email: string;
  readonly purpose: EmailCodePurpose;
  readonly captchaToken: string;
  readonly ip: string;
  readonly deviceKey?: string | null;
  readonly eligible: boolean;
}
export interface EmailVerifyInput {
  readonly email: string;
  readonly purpose: EmailCodePurpose;
  readonly code: string;
  readonly ip: string;
}

function hashDeviceKey(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
function invalidCode(): BadRequestException {
  return new BadRequestException({ error: 'invalid_code' });
}

@Injectable()
export class EmailCodeService {
  private readonly secret: string | undefined;
  private readonly ttlSeconds: number;
  private readonly maxAttempts: number;
  private readonly globalSendsPerHour: number;
  private missingKeyWarned = false;

  constructor(
    @Inject(ENV)
    env: Pick<
      Env,
      | 'EMAIL_CODE_HMAC_KEY'
      | 'EMAIL_CODE_TTL_SECONDS'
      | 'EMAIL_CODE_MAX_ATTEMPTS'
      | 'EMAIL_GLOBAL_SENDS_PER_HOUR'
    >,
    private readonly rateLimit: RateLimitService,
    @Inject(EMAIL_CODE_STORE) private readonly store: EmailCodeStore | null,
    private readonly proof: EmailProofService,
    @Inject(EMAIL_PROVIDER) private readonly emailProvider: EmailProvider,
    @Inject(CAPTCHA_PROVIDER) private readonly captchaProvider: CaptchaProvider,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.secret = env.EMAIL_CODE_HMAC_KEY;
    this.ttlSeconds = env.EMAIL_CODE_TTL_SECONDS;
    this.maxAttempts = env.EMAIL_CODE_MAX_ATTEMPTS;
    this.globalSendsPerHour = env.EMAIL_GLOBAL_SENDS_PER_HOUR;
  }

  async start(input: EmailStartInput): Promise<void> {
    const email = normalizeEmail(input.email);
    if (email === null || !EMAIL_PURPOSES.has(input.purpose)) throw new BadRequestException();
    if (
      (input.purpose === 'register' || input.purpose === 'email_change_new') &&
      isDisposableEmailDomain(email)
    ) {
      throw new BadRequestException();
    }
    this.requireKey();
    const ip = await this.rateLimit.consume({
      scope: 'email-start-ip',
      identifier: input.ip,
      ...EMAIL_START_IP_LIMIT,
    });
    if (!ip.allowed) throw this.throttled(ip.retryAfterSeconds);
    if (!(await this.verifyCaptcha(input.captchaToken, input.ip))) throw new BadRequestException();
    await this.sendAfterLimits(email, input.purpose, input.ip, input.deviceKey, input.eligible);
  }

  async startForVerifiedUser(input: {
    readonly email: string;
    readonly purpose: 'login_device';
    readonly ip: string;
    readonly deviceKey?: string | null;
  }): Promise<void> {
    const email = normalizeEmail(input.email);
    if (email === null || input.purpose !== 'login_device') throw new BadRequestException();
    this.requireKey();
    const ip = await this.rateLimit.consume({
      scope: 'email-start-ip',
      identifier: input.ip,
      ...EMAIL_START_IP_LIMIT,
    });
    if (!ip.allowed) throw this.throttled(ip.retryAfterSeconds);
    await this.sendAfterLimits(email, input.purpose, input.ip, input.deviceKey, true);
  }

  private async sendAfterLimits(
    email: string,
    purpose: EmailCodePurpose,
    ip: string,
    deviceKey: string | null | undefined,
    eligible: boolean,
  ): Promise<void> {
    const global = await this.rateLimit.consume({
      scope: 'email-start-global',
      identifier: GLOBAL_SEND_TRACKER,
      limit: this.globalSendsPerHour,
      windowSeconds: 3600,
    });
    if (!global.allowed) return;
    const cooldown = await this.rateLimit.consume({
      scope: 'email-start-cooldown',
      identifier: `${email}:${purpose}`,
      limit: 1,
      windowSeconds: EMAIL_RESEND_COOLDOWN_SECONDS,
    });
    if (!cooldown.allowed) return;
    const perEmail = await this.rateLimit.consume({
      scope: 'email-start-email',
      identifier: email,
      ...EMAIL_START_EMAIL_LIMIT,
    });
    if (!perEmail.allowed) return;
    if (deviceKey !== undefined && deviceKey !== null) {
      const device = await this.rateLimit.consume({
        scope: 'email-start-device',
        identifier: hashDeviceKey(deviceKey),
        ...EMAIL_START_DEVICE_LIMIT,
      });
      if (!device.allowed) return;
    }
    if (!eligible) return;
    const code = this.emailProvider.fixedCode ?? String(randomInt(0, 1_000_000)).padStart(6, '0');
    const store = this.requireStore();
    const key = emailCodeKey(this.codeKey(), purpose, email);
    try {
      await store.put(key, hashEmailCode(this.codeKey(), purpose, email, code), this.ttlSeconds);
      await this.emailProvider.sendCode({ to: email, purpose, code });
    } catch {
      throw new ServiceUnavailableException();
    }
  }

  async verify(input: EmailVerifyInput): Promise<{ readonly proof: string }> {
    this.requireKey();
    const ip = await this.rateLimit.consume({
      scope: 'email-verify-ip',
      identifier: input.ip,
      ...EMAIL_VERIFY_IP_LIMIT,
    });
    if (!ip.allowed) throw this.throttled(ip.retryAfterSeconds);
    const email = normalizeEmail(input.email);
    if (email === null || !EMAIL_PURPOSES.has(input.purpose) || !CODE_PATTERN.test(input.code))
      throw invalidCode();

    const store = this.requireStore();
    const codeKey = this.codeKey();
    let result: Awaited<ReturnType<EmailCodeStore['verifyAndConsume']>>;
    try {
      result = await store.verifyAndConsume(
        emailCodeKey(codeKey, input.purpose, email),
        hashEmailCode(codeKey, input.purpose, email, input.code),
        this.maxAttempts,
      );
    } catch {
      throw new ServiceUnavailableException();
    }
    if (result === 'locked_now') {
      await this.writeAudit('email_code.locked', email, input.ip);
      throw invalidCode();
    }
    if (result !== 'ok') throw invalidCode();

    try {
      const proof = await this.proof.issueEmailProof({ email, purpose: input.purpose });
      await this.writeAudit('email_code.verified', email, input.ip);
      return { proof };
    } catch {
      throw new ServiceUnavailableException();
    }
  }

  private throttled(retryAfterSeconds: number): HttpException {
    return new HttpException({ error: 'rate_limited', retryAfterSeconds }, 429);
  }

  private requireStore(): EmailCodeStore {
    if (this.store === null) throw new ServiceUnavailableException();
    return this.store;
  }

  private requireKey(): void {
    try {
      deriveEmailCodeKey(this.secret);
    } catch (error) {
      if (error instanceof EmailCodeKeyMissingError && !this.missingKeyWarned) {
        this.missingKeyWarned = true;
        this.logger.warn('email code service unavailable');
      }
      throw new ServiceUnavailableException();
    }
  }

  private codeKey(): Buffer {
    return deriveEmailCodeKey(this.secret);
  }

  private async verifyCaptcha(token: string, ip: string): Promise<boolean> {
    try {
      return await this.captchaProvider.verify(token, ip);
    } catch {
      return false;
    }
  }

  private async writeAudit(
    action: 'email_code.locked' | 'email_code.verified',
    email: string,
    ip: string,
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorRole: 'system',
        targetType: 'email',
        ip,
        metadata: { actor: 'system', email: maskEmail(email) },
      });
    } catch {
      if (action === 'email_code.verified') throw new ServiceUnavailableException();
      this.logger.warn('email code audit failed');
    }
  }
}
