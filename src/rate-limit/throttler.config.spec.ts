import { ThrottlerStorage } from '@nestjs/throttler';
import { RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_TTL_MS } from '../common/constants';
import { loadEnv } from '../config/env';
import { buildThrottlerModuleOptions } from './throttler.config';

const BASE_ENV: NodeJS.ProcessEnv = {
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:unit-test@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
};

const PROD_ENV: NodeJS.ProcessEnv = {
  ...BASE_ENV,
  APP_ORIGINS: 'https://app.example',
  NODE_ENV: 'production',
  DATABASE_URL: 'postgresql://kfa_app:unit-test@db.internal:5432/kfa?sslmode=require',
  REDIS_URL: 'rediss://:unit-test-redis-password@redis.internal:6380/0',
  OTP_PROVIDER: 'twilio',
  CAPTCHA_PROVIDER: 'recaptcha',
};

/** The function only needs the abstract storage contract, so a stub is enough. */
const STUB_STORAGE = { increment: jest.fn() } as unknown as ThrottlerStorage;

describe('buildThrottlerModuleOptions', () => {
  it('uses the shared in-memory defaults outside production', () => {
    const options = buildThrottlerModuleOptions(loadEnv({ ...BASE_ENV, NODE_ENV: 'test' }));

    expect(options).toEqual({
      throttlers: [
        { name: 'default', ttl: RATE_LIMIT_DEFAULT_TTL_MS, limit: RATE_LIMIT_DEFAULT_LIMIT },
      ],
    });
  });

  it('also applies in development and test', () => {
    for (const nodeEnv of ['development', 'test'] as const) {
      expect(() =>
        buildThrottlerModuleOptions(loadEnv({ ...BASE_ENV, NODE_ENV: nodeEnv })),
      ).not.toThrow();
    }
  });

  it('wires the provided shared storage outside production', () => {
    const options = buildThrottlerModuleOptions(
      loadEnv({ ...BASE_ENV, NODE_ENV: 'test' }),
      STUB_STORAGE,
    );

    expect(options).toMatchObject({ storage: STUB_STORAGE });
  });

  it('refuses to boot in production without a shared storage', () => {
    const env = loadEnv({ ...PROD_ENV });

    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Refusing to start/);
    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Redis-backed throttler store/);
  });

  it('accepts production once a shared storage is provided', () => {
    const options = buildThrottlerModuleOptions(loadEnv({ ...PROD_ENV }), STUB_STORAGE);

    expect(options).toMatchObject({
      storage: STUB_STORAGE,
      throttlers: [
        { name: 'default', ttl: RATE_LIMIT_DEFAULT_TTL_MS, limit: RATE_LIMIT_DEFAULT_LIMIT },
      ],
    });
  });
});
