import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { ALERT_SINK } from './alert-sink';
import { LogAlertSink } from './log-alert.sink';
import { SecurityAlertService } from './security-alert.service';

/**
 * Core of the security alerts (stage 11b-1). Deliberately not imported by
 * AppModule yet: no CounterStore provider exists, so wiring it now would fail
 * closed at boot instead of quietly counting in process memory.
 */
@Module({
  imports: [AuditModule],
  providers: [
    LogAlertSink,
    { provide: ALERT_SINK, useExisting: LogAlertSink },
    SecurityAlertService,
  ],
  exports: [SecurityAlertService],
})
export class SecurityAlertsModule {}
