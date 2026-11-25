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
    ];

    for (const alert of alerts) await sink.emit(alert);

    expect(lines).toHaveLength(3);
    expect(audit.records).toHaveLength(3);
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
    ]);
  });
});
