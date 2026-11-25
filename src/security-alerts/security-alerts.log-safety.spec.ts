import pino, { type DestinationStream } from 'pino';
import { buildRedactPaths } from '../logging/pino.config';
import type { AuditRecordInput } from '../audit/audit.service';
import { LogAlertSink, SECURITY_ALERT_AUDIT_ACTION } from './log-alert.sink';
import type { SecurityAlert } from './alert-sink';

const REDACTED = '[REDACTED]';
const EMAIL_PATTERN = /[^\s@]+@[^\s@]+\.[^\s@]+/;
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const IPV6_PATTERN = /(?:^|[^\w.-])(?:[\da-f]{1,4}:){2,7}[\da-f]{1,4}(?:$|[^\w.-])/i;
const TOKEN_PATTERN = /(?:eyJ[a-z\d_-]+\.[a-z\d_-]+|(?:token|secret|bearer)[=:][^\s,}"']+)/i;
const ALLOWED_LOG_FIELDS = new Set([
  'event',
  'kind',
  'subjectId',
  'country',
  'count',
  'windowSeconds',
  'at',
  'level',
  'msg',
  'time',
]);

class RecordingAuditService {
  readonly records: AuditRecordInput[] = [];

  async record(input: AuditRecordInput): Promise<never> {
    this.records.push(input);
    throw new Error('recording audit does not return a database row');
  }
}

function createRecordingLogger(): {
  logger: { warn: jest.Mock; debug: jest.Mock };
  lines: string[];
} {
  const lines: string[] = [];
  const stream = {
    write: (line: string): void => {
      lines.push(line);
    },
  } as unknown as DestinationStream;
  const logger = pino(
    { base: null, redact: { paths: buildRedactPaths(), censor: REDACTED } },
    stream,
  );

  return {
    logger: {
      warn: jest.fn((object: object, message: string) => logger.warn(object, message)),
      debug: jest.fn(),
    },
    lines,
  };
}

function assertSafe(serialized: string): void {
  expect(serialized).not.toMatch(EMAIL_PATTERN);
  expect(serialized).not.toMatch(IPV4_PATTERN);
  expect(serialized).not.toMatch(IPV6_PATTERN);
  expect(serialized).not.toMatch(TOKEN_PATTERN);
}

describe('LogAlertSink safety', () => {
  it('keeps all alert log lines and audit records limited to safe fields', async () => {
    const { logger, lines } = createRecordingLogger();
    const audit = new RecordingAuditService();
    const sink = new LogAlertSink(logger as never, audit as never);
    const at = new Date('2026-11-24T12:00:00.000Z');
    const alerts: SecurityAlert[] = [
      { kind: 'EMAIL_CODE_SURGE', at, count: 3, windowSeconds: 60 },
      { kind: 'DOCUMENT_VIEW_SURGE', at, subjectId: 'user-a', count: 3, windowSeconds: 60 },
      { kind: 'LOGIN_NEW_COUNTRY', at, subjectId: 'user-a', country: 'DE' },
      {
        kind: 'FAILED_LOGIN_IP_SURGE',
        at,
        count: 6,
        windowSeconds: 900,
        ip: '203.0.113.10',
      },
    ];

    for (const alert of alerts) await sink.emit(alert);

    expect(lines).toHaveLength(4);
    expect(audit.records).toHaveLength(4);
    for (const line of lines) {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      expect(Object.keys(parsed).every((key) => ALLOWED_LOG_FIELDS.has(key))).toBe(true);
      assertSafe(line);
    }
    for (const record of audit.records) {
      expect(record.action).toBe(SECURITY_ALERT_AUDIT_ACTION);
      expect(record.ip).toBeUndefined();
      expect(record.metadata).toBeDefined();
      assertSafe(JSON.stringify(record));
    }

    expect(audit.records.map((record) => record.action)).toEqual([
      'security.alert',
      'security.alert',
      'security.alert',
      'security.alert',
    ]);
  });

  it('fans out IP surge delivery without leaking the IP to logs', async () => {
    const logger = { warn: jest.fn(), debug: jest.fn() };
    const audit = new RecordingAuditService();
    const prisma = {
      user: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'owner-1', email: 'owner@example.com' },
          { id: 'admin-1', email: 'admin@example.com' },
        ]),
      },
    };
    const notifications = { create: jest.fn().mockResolvedValue(undefined) };
    const email = { sendNotice: jest.fn().mockResolvedValue(undefined) };
    const sink = new LogAlertSink(
      logger as never,
      audit as never,
      prisma as never,
      notifications as never,
      email as never,
    );

    await sink.emit({
      kind: 'FAILED_LOGIN_IP_SURGE',
      at: new Date('2026-11-24T12:00:00.000Z'),
      count: 6,
      windowSeconds: 900,
      ip: '203.0.113.10',
    });

    expect(notifications.create).toHaveBeenCalledTimes(2);
    expect(email.sendNotice).toHaveBeenCalledTimes(2);
    expect(notifications.create).toHaveBeenNthCalledWith(1, 'owner-1', 'failed_login_ip_surge', {
      ip: '203.0.113.10',
      count: 6,
      windowSeconds: 900,
    });
    expect(logger.warn).not.toHaveBeenCalledWith(
      expect.objectContaining({ ip: expect.anything() }),
    );
  });

  it('swallows notification and email delivery failures', async () => {
    const logger = { warn: jest.fn(), debug: jest.fn() };
    const prisma = {
      user: {
        findMany: jest.fn().mockResolvedValue([{ id: 'owner-1', email: 'owner@example.com' }]),
      },
    };
    const sink = new LogAlertSink(
      logger as never,
      new RecordingAuditService() as never,
      prisma as never,
      { create: jest.fn().mockRejectedValue(new Error('db down')) } as never,
      { sendNotice: jest.fn().mockRejectedValue(new Error('mail down')) } as never,
    );

    await expect(
      sink.emit({
        kind: 'FAILED_LOGIN_IP_SURGE',
        at: new Date(),
        count: 6,
        windowSeconds: 900,
        ip: '203.0.113.10',
      }),
    ).resolves.toBeUndefined();
  });
});
