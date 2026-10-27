import type { ThrottlerModuleOptions, ThrottlerStorage } from '@nestjs/throttler';
import { RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_TTL_MS } from '../common/constants';
import type { Env } from '../config/env';

/**
 * Builds the global throttler options.
 *
 * - Outside production the shared Redis store is used when `REDIS_URL` is set;
 *   otherwise the in-memory storage is fine for a single developer process.
 * - In production a shared store is mandatory: per-process counters cannot
 *   protect a multi-instance deployment, so boot is refused without one.
 */
export function buildThrottlerModuleOptions(
  env: Env,
  storage: ThrottlerStorage | null = null,
): ThrottlerModuleOptions {
  if (env.NODE_ENV === 'production' && storage === null) {
    throw new Error(
      'Refusing to start: NODE_ENV=production requires a Redis-backed throttler store. ' +
        'Set REDIS_URL so rate-limit counters are shared across instances ' +
        '(see src/rate-limit/throttler.config.ts).',
    );
  }

  return {
    throttlers: [
      {
        name: 'default',
        ttl: RATE_LIMIT_DEFAULT_TTL_MS,
        limit: RATE_LIMIT_DEFAULT_LIMIT,
      },
    ],
    ...(storage === null ? {} : { storage }),
  };
}
