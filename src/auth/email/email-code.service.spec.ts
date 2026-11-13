import { BadRequestException, HttpException, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../audit/audit.service';
import type { RateLimitDecision, RateLimitService } from '../../rate-limit/rate-limit.service';
import { FakeCaptchaProvider, type CaptchaProvider } from '../captcha/captcha.provider';
import { EMAIL_CODE_STORE } from './email-code.store';
import { InMemoryEmailCodeStore } from './email-code.store';
import { FakeEmailProvider, type EmailProvider } from './email.provider';
import {
  EMAIL_START_DEVICE_LIMIT,
  EMAIL_START_EMAIL_LIMIT,
  EMAIL_START_IP_LIMIT,
  EmailCodeService,
  EMAIL_VERIFY_IP_LIMIT,
} from './email-code.service';

const ENV = {
  EMAIL_CODE_HMAC_KEY: 'x'.repeat(32),
  EMAIL_CODE_TTL_SECONDS: 600,
  EMAIL_CODE_MAX_ATTEMPTS: 3,
  EMAIL_GLOBAL_SENDS_PER_HOUR: 500,
};
const INPUT = {
  email: 'User@Example.com',
  purpose: 'register' as const,
  captchaToken: 'fake-captcha-pass',
  ip: '203.0.113.7',
  deviceKey: 'device',
  eligible: true,
};

class Limits {
  readonly calls: Array<{ scope: string; identifier: string }> = [];
  blocked = new Set<string>();
  async consume(input: {
    scope: string;
    identifier: string;
    limit: number;
    windowSeconds: number;
  }): Promise<RateLimitDecision> {
    this.calls.push({ scope: input.scope, identifier: input.identifier });
    return { allowed: !this.blocked.has(input.scope), remaining: 1, retryAfterSeconds: 17 };
  }
  async reset(): Promise<void> {}
}
function harness(
  options: {
    key?: string;
    provider?: EmailProvider;
    store?: InMemoryEmailCodeStore | null;
    captcha?: CaptchaProvider;
  } = {},
) {
  const limits = new Limits();
  const provider = options.provider ?? new FakeEmailProvider();
  const store = options.store === undefined ? new InMemoryEmailCodeStore() : options.store;
  const audit = { record: jest.fn().mockResolvedValue(undefined) };
  const logger = { warn: jest.fn() };
  const service = new EmailCodeService(
    { ...ENV, EMAIL_CODE_HMAC_KEY: options.key ?? ENV.EMAIL_CODE_HMAC_KEY },
    limits as unknown as RateLimitService,
    store,
    { issueEmailProof: jest.fn().mockResolvedValue('proof-1') } as never,
    provider,
    options.captcha ?? new FakeCaptchaProvider(),
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );
  return { service, limits, provider, store, audit, logger };
}

describe('EmailCodeService', () => {
  it('stores a hash and sends the fake fixed code once', async () => {
    const h = harness();
    await h.service.start(INPUT);
    expect(h.limits.calls.map((x) => x.scope)).toEqual([
      'email-start-ip',
      'email-start-global',
      'email-start-cooldown',
      'email-start-email',
      'email-start-device',
    ]);
    expect(h.provider).toBeInstanceOf(FakeEmailProvider);
    const result = await h.service.verify({
      email: INPUT.email,
      purpose: INPUT.purpose,
      code: '123456',
      ip: INPUT.ip,
    });
    expect(result.proof).toBeDefined();
    expect(h.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'email_code.verified' }),
    );
  });

  it('accepts the dev captcha token outside production and sends one code', async () => {
    const h = harness({ captcha: new FakeCaptchaProvider('development') });
    const sendCode = jest.spyOn(h.provider, 'sendCode');

    await h.service.start({ ...INPUT, captchaToken: 'fake-captcha-token' });

    expect(sendCode).toHaveBeenCalledTimes(1);
    expect(sendCode).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'user@example.com', purpose: 'register' }),
    );
  });

  it('rejects a wrong captcha token outside production with the generic 400 body', async () => {
    const h = harness({ captcha: new FakeCaptchaProvider('development') });
    const sendCode = jest.spyOn(h.provider, 'sendCode');

    const error: unknown = await h.service
      .start({ ...INPUT, captchaToken: 'fake-captcha-token-wrong' })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(BadRequestException);
    expect((error as BadRequestException).getResponse()).toEqual(
      new BadRequestException().getResponse(),
    );
    expect(sendCode).not.toHaveBeenCalled();
  });

  it('runs all limiter steps for ineligible input but does not store or send', async () => {
    const h = harness();
    await h.service.start({ ...INPUT, eligible: false });
    expect(h.limits.calls).toHaveLength(5);
  });

  it('silently suppresses address caps and returns 429 for the IP cap', async () => {
    const h = harness();
    h.limits.blocked.add('email-start-email');
    await expect(h.service.start(INPUT)).resolves.toBeUndefined();
    const second = harness();
    second.limits.blocked.add('email-start-ip');
    await expect(second.service.start(INPUT)).rejects.toMatchObject({ status: 429 });
    try {
      await second.service.start(INPUT);
    } catch (error) {
      expect((error as HttpException).getResponse()).toEqual({
        error: 'rate_limited',
        retryAfterSeconds: 17,
      });
    }
  });

  it('rejects malformed and disposable registration addresses', async () => {
    const h = harness();
    await expect(h.service.start({ ...INPUT, email: 'bad' })).rejects.toBeDefined();
    await expect(h.service.start({ ...INPUT, email: 'x@mailinator.com' })).rejects.toBeDefined();
    await expect(
      h.service.start({ ...INPUT, email: 'x@mailinator.com', purpose: 'login_device' }),
    ).resolves.toBeUndefined();
  });

  it('collapses wrong, expired, locked and replayed codes to invalid_code', async () => {
    const h = harness();
    await h.service.start(INPUT);
    for (let i = 0; i < 2; i++)
      await expect(h.service.verify({ ...INPUT, code: '000000' })).rejects.toMatchObject({
        response: { error: 'invalid_code' },
      });
    await expect(h.service.verify({ ...INPUT, code: '000000' })).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    await expect(h.service.verify({ ...INPUT, code: '123456' })).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    expect(h.audit.record).toHaveBeenCalledTimes(1);
    await expect(
      h.service.verify({ ...INPUT, code: '123456', purpose: 'login_device' }),
    ).rejects.toBeDefined();
  });

  it('fails closed for a missing key and unavailable store', async () => {
    const missing = harness({ key: '' });
    await expect(missing.service.start(INPUT)).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(missing.service.verify({ ...INPUT, code: '123456' })).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    const unavailable = harness({ store: null as never });
    await expect(unavailable.service.start(INPUT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('uses the same SHA-256 device tracker as OTP', () => {
    const h = harness();
    expect(createHash('sha256').update('device').digest('hex')).toHaveLength(64);
    expect(
      EMAIL_START_IP_LIMIT.limit +
        EMAIL_START_EMAIL_LIMIT.limit +
        EMAIL_START_DEVICE_LIMIT.limit +
        EMAIL_VERIFY_IP_LIMIT.limit,
    ).toBe(40);
    expect(h.limits.calls).toEqual([]);
  });
});
