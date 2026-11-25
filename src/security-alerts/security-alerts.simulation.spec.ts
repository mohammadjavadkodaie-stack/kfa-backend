import type { AlertSink, SecurityAlert } from './alert-sink';
import type { CounterStore } from './counter-store';
import { SecurityAlertService, type SecurityAlertOptions } from './security-alert.service';
import type { KnownCountryStore } from './known-country-store';
import { InMemoryCounterStore } from './testing/in-memory-counter-store';
import { InMemoryKnownCountryStore } from './testing/in-memory-known-country-store';

class RecordingAlertSink implements AlertSink {
  readonly alerts: SecurityAlert[] = [];

  async emit(alert: SecurityAlert): Promise<void> {
    this.alerts.push(alert);
  }
}

function createService(
  options: SecurityAlertOptions,
  counterStore: CounterStore = new InMemoryCounterStore(),
  knownCountryStore: KnownCountryStore = new InMemoryKnownCountryStore(),
) {
  const sink = new RecordingAlertSink();
  const service = new SecurityAlertService(counterStore, sink, knownCountryStore, options);

  return { service, sink };
}

describe('SecurityAlertService simulations', () => {
  it('alerts exactly once when email-code traffic reaches the threshold', async () => {
    const { service, sink } = createService({
      emailCode: { threshold: 3, windowSeconds: 60 },
    });

    await service.emailCodeRequest();
    await service.emailCodeRequest();
    expect(sink.alerts).toHaveLength(0);

    await service.emailCodeRequest();
    await service.emailCodeRequest();
    await service.emailCodeRequest();

    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({ kind: 'EMAIL_CODE_SURGE', count: 3 });
  });

  it('isolates document-view surges per user', async () => {
    const { service, sink } = createService({
      documentView: { threshold: 3, windowSeconds: 60 },
    });

    await service.documentView('userA');
    await service.documentView('userA');
    await service.documentView('userB');
    expect(sink.alerts).toHaveLength(0);

    await service.documentView('userA');
    await service.documentView('userA');
    await service.documentView('userB');

    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({
      kind: 'DOCUMENT_VIEW_SURGE',
      subjectId: 'userA',
      count: 3,
    });
  });

  it('alerts once for a new login country after the first country', async () => {
    const { service, sink } = createService({ loginCountryWindowSeconds: 60 });

    await service.loginCountry('userA', 'TR');
    await service.loginCountry('userA', 'TR');
    expect(sink.alerts).toHaveLength(0);

    await service.loginCountry('userA', 'DE');
    await service.loginCountry('userA', 'DE');

    expect(sink.alerts).toHaveLength(1);
    expect(sink.alerts[0]).toMatchObject({
      kind: 'LOGIN_NEW_COUNTRY',
      subjectId: 'userA',
      country: 'DE',
    });
  });

  it('fails open when either backing store throws', async () => {
    const throwingCounters = {
      incr: jest.fn().mockRejectedValue(new Error('counter unavailable')),
    };
    const counterFailure = createService({}, throwingCounters);

    await expect(counterFailure.service.emailCodeRequest()).resolves.toBeNull();
    await expect(counterFailure.service.documentView('userA')).resolves.toBeNull();
    expect(counterFailure.sink.alerts).toHaveLength(0);

    const throwingCountries = {
      recordAndCheck: jest.fn().mockRejectedValue(new Error('country store unavailable')),
    };
    const countryFailure = createService({}, new InMemoryCounterStore(), throwingCountries);

    await expect(countryFailure.service.loginCountry('userA', 'DE')).resolves.toBeNull();
    expect(countryFailure.sink.alerts).toHaveLength(0);
  });
});
