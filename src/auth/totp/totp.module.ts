import { Module } from '@nestjs/common';
import { AuditModule } from '../../audit/audit.module';
import { PrismaModule } from '../../database/prisma.module';
import { RateLimitModule } from '../../rate-limit/rate-limit.module';
import { PrismaTotpRepository } from './prisma-totp.repository';
import { TOTP_REPOSITORY } from './totp.repository';
import { TotpService } from './totp.service';

/**
 * Second-factor state and policy. No controller here: the endpoints arrive in
 * stage 3.2c and are the only layer that checks roles.
 */
@Module({
  imports: [RateLimitModule, AuditModule, PrismaModule],
  providers: [
    // Swapped for the in-memory fake in the service tests.
    { provide: TOTP_REPOSITORY, useClass: PrismaTotpRepository },
    TotpService,
  ],
  exports: [TotpService],
})
export class TotpModule {}
