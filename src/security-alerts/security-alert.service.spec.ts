import type { AlertSink, SecurityAlert } from './alert-sink';
import type { SecurityAlertOptions } from './security-alert.service';
import { SecurityAlertService } from './security-alert.service';
import { InMemoryCounterStore } from './testing/in-memory-counter-store';
import { InMemoryKnownCountryStore } from './testing/in-memory-known-country-store';

class RecordingLogger {
  readonly debug = jest.fn();
}

class RecordingSink implements AlertSink {
  readonly alerts: SecurityAlert[] = [];

  async emit(alert: SecurityAlert): Promise<void> {
    this.alerts.push(alert);
  }
}

const ALLOWED_FIELDS = new Set(['kind', 'at', 'subjectId', 'country', 'count', 'windowSeconds']);

function createService(options: SecurityAlertOptions = {}, clock: () => number = () => Date.now()) {
  const sink = new RecordingSink();
  const service = new SecurityAlertService(
    new InMemoryCounterStore(clock),
    sink,
    new InMemoryKnownCountryStore(),
    options,
  );
  return { service, sink };
}

describe('SecurityAlertService', () => {
  it('alerts on a login from an unknown country', async () => {
    const { service, sink } = createService();

    await service.loginCountry('user-1', 'DE');

    expect(sink.alerts).toHaveLength(0);
  });

  it('alerts for a new country after the first country was stored', async () => {
    const { service, sink } = createService();

    await service.loginCountry('user-1', 'IR');
    await service.loginCountry('user-1', 'DE');

    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({ subjectId: 'user-1', country: 'DE' });
  });

  it('stays quiet for the same country', async () => {
    const { service, sink } = createService();

    await service.loginCountry('user-1', 'ir');
    await service.loginCountry('user-1', 'IR');

    expect(sink.alerts).toHaveLength(0);
  });

  it('ignores an empty or malformed country', async () => {
    const { service, sink } = createService();

    await service.loginCountry('user-1', '');
    await service.loginCountry('user-1', 'Germany');
    await service.loginCountry('user-1', 'D1');
    await service.loginCountry('user-1', 'unknown');
    await service.loginCountry('user-1', 'XX');
    await service.loginCountry('user-1', 'T1');

    expect(sink.alerts).toHaveLength(0);
  });

  it('alerts once per window for the same new country', async () => {
    // A retry storm from one country must not become a retry storm of alerts.
    const { service, sink } = createService();

    await service.loginCountry('user-1', 'IR');
    await service.loginCountry('user-1', 'DE');
    await service.loginCountry('user-1', 'DE');
    await service.loginCountry('user-1', 'DE');

    expect(sink.alerts).toHaveLength(1);
  });

  it('alerts exactly once when the email-code count reaches the threshold', async () => {
    const { service, sink } = createService({ emailCode: { threshold: 3, windowSeconds: 60 } });

    for (let i = 0; i < 6; i += 1) await service.emailCodeRequest();

    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({
      kind: 'EMAIL_CODE_SURGE',
      count: 3,
      windowSeconds: 60,
    });
  });

  it('uses the default email threshold of 50', async () => {
    const { service, sink } = createService();

    for (let i = 0; i < 49; i += 1) await service.emailCodeRequest();
    expect(sink.alerts).toHaveLength(0);

    await service.emailCodeRequest();
    expect(sink.alerts).toHaveLength(1);
  });

  it('fires one failed-login IP surge at six attempts', async () => {
    const { service, sink } = createService();

    for (let i = 0; i < 5; i += 1) await service.failedLoginIp('203.0.113.10');
    expect(sink.alerts).toHaveLength(0);

    await service.failedLoginIp('203.0.113.10');
    await service.failedLoginIp('203.0.113.10');
    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({
      kind: 'FAILED_LOGIN_IP_SURGE',
      count: 6,
      windowSeconds: 900,
      ip: '203.0.113.10',
    });
  });

  it('skips failed-login IP alerts for missing addresses', async () => {
    const { service, sink } = createService();

    await service.failedLoginIp('');
    await service.failedLoginIp('   ');

    expect(sink.alerts).toHaveLength(0);
  });

  it('counts document views per actor', async () => {
    const { service, sink } = createService({ documentView: { threshold: 2, windowSeconds: 60 } });

    for (let i = 0; i < 5; i += 1) await service.documentView('user-1');
    for (let i = 0; i < 5; i += 1) await service.documentView('user-2');

    expect(sink.alerts.map((alert) => alert.subjectId)).toEqual(['user-1', 'user-2']);
    expect(sink.alerts.map((alert) => alert.kind)).toEqual([
      'DOCUMENT_VIEW_SURGE',
      'DOCUMENT_VIEW_SURGE',
    ]);
  });

  it('opens a fresh window after the window lapses', async () => {
    // The store owns the window: a lapsed window counts from one again.
    let now = 0;
    const { service, sink } = createService(
      { documentView: { threshold: 2, windowSeconds: 60 } },
      () => now,
    );

    await service.documentView('user-1');
    await service.documentView('user-1');
    await service.documentView('user-1');
    expect(sink.alerts).toHaveLength(1);

    now += 60_000;
    await service.documentView('user-1');
    expect(sink.alerts).toHaveLength(1);

    await service.documentView('user-1');
    expect(sink.alerts).toHaveLength(2);
  });

  it('swallows counter failures', async () => {
    // Alerts must not break the request path.
    const logger = new RecordingLogger();

    const counters = { incr: jest.fn().mockRejectedValue(new Error('redis down')) };
    const service = new SecurityAlertService(
      counters,
      new RecordingSink(),
      new InMemoryKnownCountryStore(),
      {},
      logger as never,
    );

    await expect(service.emailCodeRequest()).resolves.toBeNull();
    expect(logger.debug).toHaveBeenCalledWith(
      { kind: 'EMAIL_CODE_SURGE' },
      'security_alert_failed',
    );
  });

  it('swallows sink failures', async () => {
    const logger = new RecordingLogger();
    const sink = { emit: jest.fn().mockRejectedValue(new Error('sink down')) };
    const service = new SecurityAlertService(
      new InMemoryCounterStore(),
      sink,
      new InMemoryKnownCountryStore(),
      {
        emailCode: { threshold: 1, windowSeconds: 60 },
      },
      logger as never,
    );

    await expect(service.emailCodeRequest()).resolves.toBeNull();
    expect(logger.debug).toHaveBeenCalledWith(
      { kind: 'EMAIL_CODE_SURGE' },
      'security_alert_failed',
    );
  });

  it('never carries email, phone, IP, token or file name fields', async () => {
    const { service, sink } = createService({
      emailCode: { threshold: 1, windowSeconds: 60 },
      documentView: { threshold: 1, windowSeconds: 60 },
    });

    await service.loginCountry('user-1', 'IR');
    await service.loginCountry('user-1', 'FR');
    await service.emailCodeRequest();
    await service.documentView('user-1');

    expect(sink.alerts).toHaveLength(3);
    const keys = sink.alerts.flatMap((alert) => Object.keys(alert));
    for (const key of keys) expect(ALLOWED_FIELDS.has(key)).toBe(true);
    expect(keys.join(',')).not.toMatch(/email|phone|ip|token|file/i);
  });

  it('does not call the known-country store for invalid or excluded countries', async () => {
    const store = { recordAndCheck: jest.fn() };
    const service = new SecurityAlertService(
      new InMemoryCounterStore(),
      new RecordingSink(),
      store,
    );

    await service.loginCountry('user-1', '');
    await service.loginCountry('user-1', 'unknown');
    await service.loginCountry('user-1', 'XX');
    await service.loginCountry('user-1', 'T1');

    expect(store.recordAndCheck).not.toHaveBeenCalled();
  });

  it('swallows known-country store failures', async () => {
    const store = { recordAndCheck: jest.fn().mockRejectedValue(new Error('redis down')) };
    const sink = new RecordingSink();
    const service = new SecurityAlertService(new InMemoryCounterStore(), sink, store);

    await expect(service.loginCountry('user-1', 'DE')).resolves.toBeNull();
    expect(sink.alerts).toHaveLength(0);
  });
});
