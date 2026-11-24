import { Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import type { AlertSink, SecurityAlert } from './alert-sink';

/**
 * Dotted, lower case like the other audit actions (`user.login`, `admin.user.block`).
 * `audit_log.action` is a free-text column, so this needs no migration.
 */
export const SECURITY_ALERT_AUDIT_ACTION = 'security.alert';

/**
 * Default sink: one structured, redacted warn line plus an audit row. A real
 * Telegram/SMS sink replaces this provider without touching the detectors.
 */
@Injectable()
export class LogAlertSink implements AlertSink {
  constructor(
    private readonly logger: PinoLogger,
    private readonly audit: AuditService,
  ) {}

  async emit(alert: SecurityAlert): Promise<void> {
    // Exactly one warn line per alert; field names are covered by the pino redaction config.
    this.logger.warn(
      {
        event: 'security_alert',
        kind: alert.kind,
        subjectId: alert.subjectId,
        country: alert.country,
        count: alert.count,
        windowSeconds: alert.windowSeconds,
        at: alert.at.toISOString(),
      },
      'security alert',
    );

    await this.recordAudit(alert);
  }

  private async recordAudit(alert: SecurityAlert): Promise<void> {
    try {
      await this.audit.record({
        action: SECURITY_ALERT_AUDIT_ACTION,
        // The subject is the affected user when there is one; surges are system events.
        targetType: alert.subjectId ? 'user' : null,
        targetId: alert.subjectId ?? null,
        // Same fields as the log line: no raw IP, AuditService redacts metadata anyway.
        metadata: {
          kind: alert.kind,
          country: alert.country,
          count: alert.count,
          windowSeconds: alert.windowSeconds,
          at: alert.at.toISOString(),
        },
      });
    } catch {
      // The warning already shipped; an audit hiccup must not hide the alert.
      this.logger.debug({ kind: alert.kind }, 'security alert audit write failed');
    }
  }
}
