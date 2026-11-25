import { Inject, Injectable, Optional } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { EMAIL_PROVIDER, type EmailProvider } from '../auth/email/email.provider';
import {
  NOTIFICATION_REPOSITORY,
  type NotificationRepository,
} from '../notifications/notification.repository';
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
    @Optional() private readonly prisma?: PrismaService,
    @Optional()
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notifications?: NotificationRepository,
    @Optional() @Inject(EMAIL_PROVIDER) private readonly email?: EmailProvider,
  ) {}

  async emit(alert: SecurityAlert): Promise<void> {
    if (alert.kind === 'FAILED_LOGIN_IP_SURGE') await this.deliverFailedLoginIpSurge(alert);
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

  private async deliverFailedLoginIpSurge(alert: SecurityAlert): Promise<void> {
    if (this.prisma === undefined || this.notifications === undefined || this.email === undefined)
      return;
    if (typeof alert.ip !== 'string' || alert.ip.length === 0) return;

    try {
      const recipients = await this.prisma.user.findMany({
        where: { role: { in: ['OWNER', 'ADMIN'] }, email: { not: null } },
        select: { id: true, email: true },
      });
      const params = { ip: alert.ip, count: 6, windowSeconds: 900 };

      for (const recipient of recipients) {
        if (recipient.email === null) continue;
        try {
          await this.notifications.create('' + recipient.id, 'failed_login_ip_surge', params);
        } catch {
          this.logger.debug({ kind: alert.kind }, 'security alert notification write failed');
        }
        try {
          await this.email.sendNotice({ to: recipient.email, kind: 'failed_login_ip_surge' });
        } catch {
          this.logger.debug({ kind: alert.kind }, 'security alert email delivery failed');
        }
      }
    } catch {
      this.logger.debug({ kind: alert.kind }, 'security alert recipient lookup failed');
    }
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
