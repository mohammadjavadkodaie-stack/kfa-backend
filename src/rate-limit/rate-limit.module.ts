import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { RateLimitService } from './rate-limit.service';
import {
  createRateLimitRedisClient,
  REDIS_CLIENT,
  RedisThrottlerStorage,
  type RateLimitRedisClient,
} from './redis-throttler.storage';
import { buildThrottlerModuleOptions } from './throttler.config';

/**
 * Owns the shared Redis client and the throttler storage.
 *
 * Kept separate so `ThrottlerModule.forRootAsync` can inject them: a dynamic
 * module only resolves dependencies from its own `imports`, never from the
 * module that imports it.
 */
@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [ENV],
      useFactory: (env: Env): RateLimitRedisClient | null =>
        // No REDIS_URL (development / test only) means no shared store.
        env.REDIS_URL === undefined ? null : createRateLimitRedisClient(env),
    },
    RedisThrottlerStorage,
  ],
  exports: [REDIS_CLIENT, RedisThrottlerStorage],
})
class RateLimitStoreModule {}

/**
 * Rate limiting wiring.
 *
 * `ThrottlerModule` is global, so the `THROTTLER_OPTIONS` / storage providers
 * exported by this module are what the `ThrottlerGuard` registered in
 * `AppModule` uses. No connection is opened at boot (`lazyConnect`): a Redis
 * outage surfaces as a 503 on rate-limited requests, never as a boot hang.
 */
@Module({
  imports: [
    RateLimitStoreModule,
    ThrottlerModule.forRootAsync({
      imports: [RateLimitStoreModule],
      inject: [ENV, REDIS_CLIENT, RedisThrottlerStorage],
      useFactory: (env: Env, client: RateLimitRedisClient | null, storage: RedisThrottlerStorage) =>
        buildThrottlerModuleOptions(env, client === null ? null : storage),
    }),
  ],
  providers: [RateLimitService],
  exports: [RateLimitService],
})
export class RateLimitModule {}
