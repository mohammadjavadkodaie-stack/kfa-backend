import { RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_TTL_MS } from '../common/constants';
import { loadEnv } from '../config/env';
import { buildThrottlerModuleOptions } from './throttler.config';

describe('buildThrottlerModuleOptions', () => {
  it('uses the shared in-memory defaults outside production', () => {
    const options = buildThrottlerModuleOptions(
      loadEnv({ APP_ORIGINS: 'http://localhost:3000', NODE_ENV: 'test' }),
    );

    expect(options).toEqual([
      { name: 'default', ttl: RATE_LIMIT_DEFAULT_TTL_MS, limit: RATE_LIMIT_DEFAULT_LIMIT },
    ]);
  });

  it('also applies in development and test', () => {
    for (const nodeEnv of ['development', 'test'] as const) {
      expect(() =>
        buildThrottlerModuleOptions(
          loadEnv({ APP_ORIGINS: 'http://localhost:3000', NODE_ENV: nodeEnv }),
        ),
      ).not.toThrow();
    }
  });

  it('refuses to boot in production until a Redis store is wired', () => {
    const env = loadEnv({ APP_ORIGINS: 'https://app.example', NODE_ENV: 'production' });

    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Refusing to start/);
    expect(() => buildThrottlerModuleOptions(env)).toThrow(/Redis-backed throttler store/);
  });
});
