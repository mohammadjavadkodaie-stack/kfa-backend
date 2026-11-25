import { Module, forwardRef } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../database/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { ALERT_SINK } from './alert-sink';
import { COUNTER_STORE } from './counter-store';
import { KNOWN_COUNTRY_STORE } from './known-country-store';
import { LogAlertSink } from './log-alert.sink';
import { RedisCounterStore } from './redis-counter-store';
import { RedisKnownCountryStore } from './redis-known-country-store';
import { SecurityAlertService } from './security-alert.service';

/**
 * Core wiring for the security alerts and their shared Redis counter.
 */
@Module({
  imports: [
    AuditModule,
    RateLimitModule,
    PrismaModule,
    NotificationsModule,
    forwardRef(() => AuthModule),
  ],
  providers: [
    RedisCounterStore,
    { provide: COUNTER_STORE, useExisting: RedisCounterStore },
    RedisKnownCountryStore,
    { provide: KNOWN_COUNTRY_STORE, useExisting: RedisKnownCountryStore },
    LogAlertSink,
    { provide: ALERT_SINK, useExisting: LogAlertSink },
    SecurityAlertService,
  ],
  exports: [SecurityAlertService],
})
export class SecurityAlertsModule {}
