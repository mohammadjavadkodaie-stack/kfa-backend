import { Module } from '@nestjs/common';
import { AuditModule } from '../../audit/audit.module';
import { PrismaModule } from '../../database/prisma.module';
import { RateLimitModule } from '../../rate-limit/rate-limit.module';
import { REDIS_CLIENT } from '../../rate-limit/redis-throttler.storage';
import { PrismaTotpRepository } from './prisma-totp.repository';
import { TOTP_REPOSITORY } from './totp.repository';
import {
  InMemoryTotpRotationStore,
  RedisTotpRotationStore,
  TOTP_ROTATION_STORE,
  type TotpRotationRedisClient,
  type TotpRotationStore,
} from './totp-rotation.store';
import { TotpService } from './totp.service';

/**
 * Second-factor state and policy. The endpoints live in `AuthModule`, which is
 * where the session repository a step-up has to stamp belongs.
 */
@Module({
  imports: [RateLimitModule, AuditModule, PrismaModule],
  providers: [
    // Swapped for the in-memory fake in the service tests.
    { provide: TOTP_REPOSITORY, useClass: PrismaTotpRepository },
    {
      // Production has REDIS_URL (required), so the pending replacement survives
      // a restart and is shared by every instance. Development and the API
      // suites fall back to the in-memory store.
      provide: TOTP_ROTATION_STORE,
      inject: [REDIS_CLIENT],
      useFactory: (client: unknown): TotpRotationStore =>
        client === null || client === undefined
          ? new InMemoryTotpRotationStore()
          : new RedisTotpRotationStore(client as TotpRotationRedisClient),
    },
    TotpService,
  ],
  // The admin reset needs the store itself, not the enrollment policy.
  exports: [TotpService, TOTP_REPOSITORY],
})
export class TotpModule {}
