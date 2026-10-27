import type { ThrottlerModuleOptions } from '@nestjs/throttler';
import { RATE_LIMIT_DEFAULT_LIMIT, RATE_LIMIT_DEFAULT_TTL_MS } from '../common/constants';
import type { Env } from '../config/env';

/**
 * Rate limiting is currently backed by the in-memory throttler storage, which
 * only works for a single instance. Production therefore refuses to boot until
 * a shared (Redis) store is wired - same rule as the frontend.
 */
export function buildThrottlerModuleOptions(env: Env): ThrottlerModuleOptions {
  if (env.NODE_ENV === 'production') {
    throw new Error(
      'Refusing to start: NODE_ENV=production requires a Redis-backed throttler store. ' +
        'In-memory rate limiting cannot protect a multi-instance deployment ' +
        '(see src/rate-limit/throttler.config.ts).',
    );
  }

  return [
    {
      name: 'default',
      ttl: RATE_LIMIT_DEFAULT_TTL_MS,
      limit: RATE_LIMIT_DEFAULT_LIMIT,
    },
  ];
}
