import { RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_TTL_MS } from '../common/constants';
import { loadEnv } from '../config/env';
import { buildThrottlerModuleOptions } from './throttler.config';

const BASE_ENV: NodeJS.ProcessEnv = {
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:unit-test@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
};

describe('buildThrottlerModuleOptions', () => {
  it('uses the shared in-memory defaults outside production', () => {
    const options = buildThrottlerModuleOptions(loadEnv({ ...BASE_ENV, NODE_ENV: 'test' }));

    expect(options).toEqual([
      { name: 'default', ttl: RATE_LIMIT_DEFAULT_TTL_MS, limit: RATE_LIMIT_DEFAULT_LIMIT },
    ]);
  });

  it('also applies in development and test', () => {
    for (const nodeEnv of ['development', 'test'] as const) {
      expect(() =>
        buildThrottlerModuleOptions(loadEnv({ ...BASE_ENV, NODE_ENV: nodeEnv })),
      ).not.toThrow();
    }
  });

  it('refuses to boot in production until a Redis store is wired', () => {
    const env = loadEnv({
      ...BASE_ENV,
      APP_ORIGINS: 'https://app.example',
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://kfa_app:unit-test@db.internal:5432/kfa?sslmode=require',
    });

    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Refusing to start/);
    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Redis-backed throttler store/);
  });
});
