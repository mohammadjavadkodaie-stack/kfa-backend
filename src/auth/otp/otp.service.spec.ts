import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../audit/audit.service';
import type { RateLimitDecision, RateLimitService } from '../../rate-limit/rate-limit.service';
import { maskPhone } from '../phone';
import {
  OTP_RESEND_COOLDOWN_SECONDS,
  OTP_START_DEVICE_LIMIT,
  OTP_START_IP_LIMIT,
  OTP_START_PHONE_LIMIT,
  OTP_VERIFY_IP_LIMIT,
  OTP_VERIFY_PHONE_LIMIT,
  OtpService,
  type OtpRequestContext,
} from './otp.service';
import type { OtpContext, OtpProvider } from './otp.provider';
import type { CaptchaProvider } from '../captcha/captcha.provider';
import type { ProofPurpose, ProofTokenService } from './proof-token';

const PHONE = '+14155552671';
const FORMATTED_PHONE = '+1 (415) 555-2671';
const CONTEXT: OtpRequestContext = { ip: '203.0.113.7', deviceKey: 'device-1', requestId: 'req-1' };
const START_BODY = { phone: FORMATTED_PHONE, purpose: 'login', captchaToken: 'captcha-ok' };
const VERIFY_BODY = { phone: FORMATTED_PHONE, purpose: 'login', code: '123456' };

interface ConsumeInput {
  readonly scope: string;
  readonly identifier: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

interface Counter {
  hits: number;
  expiresAt: number;
}

/**
 * In-memory fixed window with the same semantics as the Redis one, so the tests
 * exercise the real ordering of the checks instead of a scripted mock.
 */
class FakeRateLimit {
  private readonly counters = new Map<string, Counter>();
  readonly calls: ConsumeInput[] = [];
  readonly resets: { scope: string; identifier: string }[] = [];
  unavailable = false;
  private now = 0;

  async consume(input: ConsumeInput): Promise<RateLimitDecision> {
    if (this.unavailable) throw new ServiceUnavailableException();

    this.calls.push({ ...input });

    const key = `${input.scope}:${input.identifier}`;
    const windowMs = input.windowSeconds * 1_000;
    const current = this.counters.get(key);
    const counter =
      current !== undefined && current.expiresAt > this.now
        ? current
        : { hits: 0, expiresAt: this.now + windowMs };

    counter.hits += 1;
    this.counters.set(key, counter);

    const allowed = counter.hits <= input.limit;

    return {
      allowed,
      remaining: Math.max(0, input.limit - counter.hits),
      retryAfterSeconds: allowed ? 0 : Math.ceil((counter.expiresAt - this.now) / 1_000),
    };
  }

  async reset(input: { scope: string; identifier: string }): Promise<void> {
    if (this.unavailable) throw new ServiceUnavailableException();

    this.resets.push({ ...input });
    this.counters.delete(`${input.scope}:${input.identifier}`);
  }

  /** Pre-fills a bucket, e.g. to simulate a device that exhausted its budget. */
  seed(scope: string, identifier: string, hits: number, windowSeconds: number): void {
    this.counters.set(`${scope}:${identifier}`, {
      hits,
      expiresAt: this.now + windowSeconds * 1_000,
    });
  }

  hits(scope: string, identifier: string): number {
    return this.counters.get(`${scope}:${identifier}`)?.hits ?? 0;
  }

  scopes(): string[] {
    return [...new Set(this.calls.map((call) => call.scope))];
  }

  advance(seconds: number): void {
    this.now += seconds * 1_000;
  }
}

class FakeOtpProvider {
  readonly starts: string[] = [];
  readonly purposes: string[] = [];
  readonly checks: { phoneE164: string; code: string }[] = [];
  correctCode = VERIFY_BODY.code;
  failStart = false;
  failCheck = false;

  async start(phoneE164: string, context: OtpContext): Promise<{ challengeRef: string | null }> {
    if (this.failStart) throw new Error('provider down');

    this.starts.push(phoneE164);
    this.purposes.push(context.purpose);

    return { challengeRef: null };
  }

  async check(phoneE164: string, code: string): Promise<boolean> {
    if (this.failCheck) throw new Error('provider down');

    this.checks.push({ phoneE164, code });

    return code === this.correctCode;
  }
}

class FakeCaptcha {
  readonly calls: { token: string; ip: string | undefined }[] = [];
  pass = true;
  throwError = false;

  async verify(token: string, ip?: string): Promise<boolean> {
    if (this.throwError) throw new Error('captcha down');

    this.calls.push({ token, ip });

    return this.pass;
  }
}

class FakeProof {
  readonly issued: string[] = [];
  readonly purposes: string[] = [];
  fail = false;

  async issue(phoneE164: string, purpose: ProofPurpose): Promise<string> {
    if (this.fail) throw new ServiceUnavailableException();

    this.issued.push(phoneE164);
    this.purposes.push(purpose);

    return `proof-${this.issued.length}`;
  }
}

function createHarness(env: { globalSendsPerHour?: number } = {}) {
  const rateLimit = new FakeRateLimit();
  const otpProvider = new FakeOtpProvider();
  const captcha = new FakeCaptcha();
  const proof = new FakeProof();
  const audit = { record: jest.fn().mockResolvedValue(undefined) };
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn() };

  const service = new OtpService(
    { OTP_GLOBAL_SENDS_PER_HOUR: env.globalSendsPerHour ?? 500 },
    rateLimit as unknown as RateLimitService,
    proof as unknown as ProofTokenService,
    otpProvider as unknown as OtpProvider,
    captcha as unknown as CaptchaProvider,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, rateLimit, otpProvider, captcha, proof, audit, logger };
}

type Harness = ReturnType<typeof createHarness>;

function recordedActions(audit: Harness['audit']): string[] {
  return audit.record.mock.calls.map((call) => (call[0] as { action: string }).action);
}

describe('OtpService.start', () => {
  it('sends a code and reports acceptance for a valid request', async () => {
    const { service, rateLimit, otpProvider, captcha, audit } = createHarness();

    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });

    // The number is normalized before it reaches the provider or any tracker.
    expect(otpProvider.starts).toEqual([PHONE]);
    // The purpose the caller asked the code for travels with the challenge.
    expect(otpProvider.purposes).toEqual(['login']);
    expect(captcha.calls).toEqual([{ token: 'captcha-ok', ip: CONTEXT.ip }]);
    expect(rateLimit.calls.map((call) => [call.scope, call.identifier])).toEqual([
      ['otp-start-ip', CONTEXT.ip],
      ['otp-start-global', 'otp-send-global'],
      ['otp-start-cooldown', PHONE],
      ['otp-start-phone', PHONE],
      ['otp-start-device', createHash('sha256').update('device-1', 'utf8').digest('hex')],
    ]);
    // A send is not an auditable event; only verification and lockouts are.
    expect(audit.record).not.toHaveBeenCalled();
  });

  it.each([
    ['a missing captcha token', { phone: FORMATTED_PHONE, purpose: 'login' }],
    ['a missing purpose', { phone: FORMATTED_PHONE, captchaToken: 'captcha-ok' }],
    ['an unknown purpose', { ...START_BODY, purpose: 'admin' }],
    ['an extra field', { ...START_BODY, isAdmin: true }],
    ['a non-string phone', { phone: 14155552671, purpose: 'login', captchaToken: 'captcha-ok' }],
    [
      'an oversized phone',
      { phone: `+${'1'.repeat(20)}`, purpose: 'login', captchaToken: 'captcha-ok' },
    ],
    [
      'an oversized captcha token',
      { phone: FORMATTED_PHONE, purpose: 'login', captchaToken: 'x'.repeat(2049) },
    ],
    ['a non-object body', 'phone=+14155552671'],
    ['null', null],
  ])('rejects %s with a generic 400 before any side effect', async (_label, body) => {
    const { service, rateLimit, otpProvider, captcha } = createHarness();

    await expect(service.start(body, CONTEXT)).rejects.toBeInstanceOf(BadRequestException);
    expect(rateLimit.calls).toEqual([]);
    expect(captcha.calls).toEqual([]);
    expect(otpProvider.starts).toEqual([]);
  });

  it('rejects a failed captcha with the same generic 400', async () => {
    const { service, captcha, rateLimit, otpProvider } = createHarness();
    captcha.pass = false;

    await expect(service.start(START_BODY, CONTEXT)).rejects.toBeInstanceOf(BadRequestException);
    expect(otpProvider.starts).toEqual([]);
    // The IP is still billed: a captcha farm must burn the same budget.
    expect(rateLimit.scopes()).toEqual(['otp-start-ip']);
  });

  it('treats a broken captcha provider as a failed captcha', async () => {
    const { service, captcha, otpProvider } = createHarness();
    captcha.throwError = true;

    await expect(service.start(START_BODY, CONTEXT)).rejects.toBeInstanceOf(BadRequestException);
    expect(otpProvider.starts).toEqual([]);
  });

  it('rejects an unparseable phone with a generic 400', async () => {
    const { service, otpProvider, rateLimit } = createHarness();

    await expect(
      service.start(
        { phone: 'not-a-phone', purpose: 'login', captchaToken: 'captcha-ok' },
        CONTEXT,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(otpProvider.starts).toEqual([]);
    // Nothing phone-bound is recorded, so the input cannot be probed via limits.
    expect(rateLimit.scopes()).toEqual(['otp-start-ip']);
  });

  it('throttles with a retry hint once the IP budget is spent', async () => {
    const { service, captcha, rateLimit, otpProvider } = createHarness();

    rateLimit.seed('otp-start-ip', CONTEXT.ip, OTP_START_IP_LIMIT.limit, 600);

    const result = await service.start(START_BODY, CONTEXT);

    expect(result.outcome).toBe('throttled');
    expect(result).toMatchObject({ retryAfterSeconds: expect.any(Number) as number });
    // The cheapest check runs first: no captcha call, no provider call.
    expect(captcha.calls).toEqual([]);
    expect(otpProvider.starts).toEqual([]);
    expect(rateLimit.scopes()).toEqual(['otp-start-ip']);
  });

  it('answers exactly like a send while the resend cooldown is active', async () => {
    const { service, otpProvider, rateLimit } = createHarness();

    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });
    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });

    expect(otpProvider.starts).toEqual([PHONE]);
    // The blocked probe still spends cooldown budget, but never the phone cap.
    expect(rateLimit.hits('otp-start-cooldown', PHONE)).toBe(2);
    expect(rateLimit.hits('otp-start-phone', PHONE)).toBe(1);
  });

  it('silently stops sending once the hourly per-phone cap is reached', async () => {
    const { service, otpProvider, rateLimit } = createHarness();

    for (let attempt = 0; attempt < OTP_START_PHONE_LIMIT.limit; attempt += 1) {
      await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });
      rateLimit.advance(OTP_RESEND_COOLDOWN_SECONDS + 1);
    }

    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });
    expect(otpProvider.starts).toHaveLength(OTP_START_PHONE_LIMIT.limit);
    expect(rateLimit.hits('otp-start-phone', PHONE)).toBe(OTP_START_PHONE_LIMIT.limit + 1);
  });

  it('silently stops sending once the hourly per-device cap is reached', async () => {
    const { service, otpProvider, rateLimit } = createHarness();
    const deviceHash = createHash('sha256').update('device-1', 'utf8').digest('hex');

    rateLimit.seed('otp-start-device', deviceHash, OTP_START_DEVICE_LIMIT.limit, 3_600);

    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });
    expect(otpProvider.starts).toEqual([]);
    // Only the hash of the device key ever reaches the limiter.
    expect(rateLimit.calls.map((call) => call.identifier)).not.toContain('device-1');
  });

  it('keeps sending when no device key is supplied', async () => {
    const { service, otpProvider, rateLimit } = createHarness();

    await expect(service.start(START_BODY, { ...CONTEXT, deviceKey: null })).resolves.toEqual({
      outcome: 'accepted',
    });
    expect(otpProvider.starts).toEqual([PHONE]);
    expect(rateLimit.scopes()).not.toContain('otp-start-device');
  });

  it('applies the deployment-wide send cap before any provider call', async () => {
    const { service, otpProvider, rateLimit } = createHarness({ globalSendsPerHour: 1 });

    await expect(service.start(START_BODY, CONTEXT)).resolves.toEqual({ outcome: 'accepted' });
    rateLimit.advance(OTP_RESEND_COOLDOWN_SECONDS + 1);

    const result = await service.start(
      { ...START_BODY, phone: '+14155550000' },
      { ...CONTEXT, deviceKey: null },
    );

    expect(result.outcome).toBe('throttled');
    expect(otpProvider.starts).toEqual([PHONE]);
  });

  it('returns 503 when the OTP provider fails', async () => {
    const { service, otpProvider } = createHarness();
    otpProvider.failStart = true;

    await expect(service.start(START_BODY, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('fails closed when the rate limiter is unavailable', async () => {
    const { service, rateLimit, otpProvider } = createHarness();
    rateLimit.unavailable = true;

    await expect(service.start(START_BODY, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(otpProvider.starts).toEqual([]);
  });
});

describe('OtpService.verify', () => {
  it('issues a proof and clears the attempt budget for the right code', async () => {
    const { service, otpProvider, proof, rateLimit, audit } = createHarness();

    await expect(service.verify(VERIFY_BODY, CONTEXT)).resolves.toEqual({
      outcome: 'verified',
      proof: 'proof-1',
    });

    // Only the normalized number is checked, never the free-form input.
    expect(otpProvider.checks).toEqual([{ phoneE164: PHONE, code: '123456' }]);
    expect(proof.issued).toEqual([PHONE]);
    // The proof is minted for the purpose the code was verified for.
    expect(proof.purposes).toEqual(['login']);
    expect(rateLimit.resets).toEqual([{ scope: 'otp-verify-phone', identifier: PHONE }]);
    expect(rateLimit.hits('otp-verify-phone', PHONE)).toBe(0);
    expect(audit.record).toHaveBeenCalledTimes(1);

    const record = audit.record.mock.calls[0]?.[0] as {
      action: string;
      actorRole: string;
      targetType: string;
      requestId: string;
      ip: string;
      metadata: { actor: string; phone: string };
    };

    expect(record).toMatchObject({
      action: 'otp.verified',
      actorRole: 'system',
      targetType: 'phone',
      requestId: CONTEXT.requestId,
      ip: CONTEXT.ip,
      metadata: { actor: 'system', phone: maskPhone(PHONE) },
    });
    // The audit row carries a masked number, never the raw one.
    expect(JSON.stringify(record)).not.toContain('5552671');
  });

  it.each([
    ['a non-numeric code', { phone: FORMATTED_PHONE, purpose: 'login', code: '12345a' }],
    ['a short code', { phone: FORMATTED_PHONE, purpose: 'login', code: '12345' }],
    ['a missing phone', { purpose: 'login', code: '123456' }],
    ['a missing purpose', { phone: FORMATTED_PHONE, code: '123456' }],
    ['an unknown purpose', { ...VERIFY_BODY, purpose: 'phone_change' }],
    ['an extra field', { ...VERIFY_BODY, attempt: 1 }],
    ['a non-object body', 'code=123456'],
    ['null', null],
  ])('rejects %s as a generic invalid code', async (_label, body) => {
    const { service, rateLimit, otpProvider, audit } = createHarness();

    await expect(service.verify(body, CONTEXT)).resolves.toEqual({ outcome: 'rejected' });
    expect(rateLimit.calls).toEqual([]);
    expect(otpProvider.checks).toEqual([]);
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('rejects a wrong code without issuing a proof', async () => {
    const { service, proof, rateLimit, audit } = createHarness();

    await expect(service.verify({ ...VERIFY_BODY, code: '000000' }, CONTEXT)).resolves.toEqual({
      outcome: 'rejected',
    });

    expect(proof.issued).toEqual([]);
    expect(rateLimit.resets).toEqual([]);
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('rejects an unparseable phone as an invalid code', async () => {
    const { service, otpProvider } = createHarness();

    await expect(
      service.verify({ phone: 'call-me', purpose: 'login', code: '123456' }, CONTEXT),
    ).resolves.toEqual({
      outcome: 'rejected',
    });
    expect(otpProvider.checks).toEqual([]);
  });

  it('locks the phone out after the attempt budget and audits it once', async () => {
    const { service, otpProvider, proof, rateLimit, audit } = createHarness();
    const wrong = { ...VERIFY_BODY, code: '000000' };

    for (let attempt = 0; attempt < OTP_VERIFY_PHONE_LIMIT.limit; attempt += 1) {
      await expect(service.verify(wrong, CONTEXT)).resolves.toEqual({ outcome: 'rejected' });
    }

    await expect(service.verify(wrong, CONTEXT)).resolves.toEqual({ outcome: 'rejected' });
    await expect(service.verify(wrong, CONTEXT)).resolves.toEqual({ outcome: 'rejected' });

    // The 6th and 7th attempts were refused before the provider was consulted.
    expect(otpProvider.checks).toHaveLength(OTP_VERIFY_PHONE_LIMIT.limit);
    expect(recordedActions(audit)).toEqual(['otp.locked']);
    expect(proof.issued).toEqual([]);
    expect(rateLimit.hits('otp-verify-phone', PHONE)).toBe(OTP_VERIFY_PHONE_LIMIT.limit + 2);
  });

  it('refuses even the right code while the lockout lasts, then accepts it', async () => {
    const { service, otpProvider, proof, rateLimit } = createHarness();

    for (let attempt = 0; attempt < OTP_VERIFY_PHONE_LIMIT.limit + 1; attempt += 1) {
      await service.verify({ ...VERIFY_BODY, code: '000000' }, CONTEXT);
    }

    await expect(service.verify(VERIFY_BODY, CONTEXT)).resolves.toEqual({ outcome: 'rejected' });
    expect(otpProvider.checks).toHaveLength(OTP_VERIFY_PHONE_LIMIT.limit);

    rateLimit.advance(OTP_VERIFY_PHONE_LIMIT.windowSeconds);

    await expect(service.verify(VERIFY_BODY, CONTEXT)).resolves.toEqual({
      outcome: 'verified',
      proof: 'proof-1',
    });
    expect(proof.issued).toEqual([PHONE]);
  });

  it('mints the proof for the purpose the code was verified for', async () => {
    const { service, proof } = createHarness();

    await expect(service.verify({ ...VERIFY_BODY, purpose: 'register' }, CONTEXT)).resolves.toEqual(
      { outcome: 'verified', proof: 'proof-1' },
    );
    expect(proof.purposes).toEqual(['register']);
  });
});

describe('OtpService.verify failure modes', () => {
  it('throttles with a retry hint once the IP attempt budget is spent', async () => {
    const { service, otpProvider, rateLimit } = createHarness();

    for (let index = 0; index < OTP_VERIFY_IP_LIMIT.limit; index += 1) {
      const phone = `+1415555${String(index).padStart(4, '0')}`;

      await expect(
        service.verify({ phone, purpose: 'login', code: '000000' }, CONTEXT),
      ).resolves.toEqual({
        outcome: 'rejected',
      });
    }

    const result = await service.verify(VERIFY_BODY, CONTEXT);

    expect(result.outcome).toBe('throttled');
    expect(result).toMatchObject({ retryAfterSeconds: expect.any(Number) as number });
    // The refused request never reached the provider, even with the right code.
    expect(otpProvider.checks).toHaveLength(OTP_VERIFY_IP_LIMIT.limit);
    expect(rateLimit.hits('otp-verify-ip', CONTEXT.ip)).toBe(OTP_VERIFY_IP_LIMIT.limit + 1);
  });

  it('returns 503 when the code check fails unexpectedly', async () => {
    const { service, otpProvider, proof } = createHarness();
    otpProvider.failCheck = true;

    await expect(service.verify(VERIFY_BODY, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(proof.issued).toEqual([]);
  });

  it('fails closed when the rate limiter is unavailable', async () => {
    const { service, rateLimit, otpProvider } = createHarness();
    rateLimit.unavailable = true;

    await expect(service.verify(VERIFY_BODY, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(otpProvider.checks).toEqual([]);
  });

  it('returns 503 when the success audit cannot be written', async () => {
    const { service, proof, audit, logger } = createHarness();
    audit.record.mockRejectedValue(new Error('db down'));

    // The failure is surfaced, not swallowed: a verified login must be audited.
    await expect(service.verify(VERIFY_BODY, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(proof.issued).toEqual([PHONE]);
    expect(recordedActions(audit)).toEqual(['otp.verified']);
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  it('keeps the lockout audit best effort so the answer stays generic', async () => {
    const { service, audit, logger } = createHarness();
    audit.record.mockRejectedValue(new Error('db down'));

    for (let attempt = 0; attempt <= OTP_VERIFY_PHONE_LIMIT.limit; attempt += 1) {
      await expect(service.verify({ ...VERIFY_BODY, code: '000000' }, CONTEXT)).resolves.toEqual({
        outcome: 'rejected',
      });
    }

    expect(recordedActions(audit)).toEqual(['otp.locked']);
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });
});
