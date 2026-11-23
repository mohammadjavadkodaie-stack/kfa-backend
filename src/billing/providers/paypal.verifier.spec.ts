import type { PayPalApi } from './paypal.api';
import { PayPalWebhookVerifier } from './paypal.verifier';

const WEBHOOK_ID = 'WH-123456789';

const HEADERS = {
  'paypal-transmission-id': 'transmission-1',
  'paypal-transmission-time': '2026-11-22T10:00:00Z',
  'paypal-cert-url': 'https://api.paypal.com/v1/notifications/certs/cert-1',
  'paypal-auth-algo': 'SHA256withRSA',
  'paypal-transmission-sig': 'signature-1',
};

function event(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'WH-EVENT-1',
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
      id: 'CAPTURE-1',
      amount: { value: '4.20', currency_code: 'USD' },
      supplementary_data: { related_ids: { order_id: 'ORDER-1', capture_id: 'CAPTURE-1' } },
    },
    ...overrides,
  };
}

class FakeApi {
  readonly calls: { path: string; body?: unknown }[] = [];
  status: unknown = 'SUCCESS';
  fails = false;

  async json<T>(path: string, request: { method: string; body?: unknown }): Promise<T> {
    this.calls.push({ path, body: request.body });

    if (this.fails) throw new Error('paypal unavailable');

    return { verification_status: this.status } as unknown as T;
  }
}

function verifier(api = new FakeApi()): {
  readonly verifier: PayPalWebhookVerifier;
  readonly api: FakeApi;
} {
  return { verifier: new PayPalWebhookVerifier(api as unknown as PayPalApi, WEBHOOK_ID), api };
}

function body(payload: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

describe('PayPalWebhookVerifier', () => {
  it('accepts a capture PayPal confirmed and names the order', async () => {
    const { verifier: subject, api } = verifier();

    await expect(subject.verify(body(event()), HEADERS)).resolves.toEqual({
      eventId: 'WH-EVENT-1',
      providerPaymentId: 'ORDER-1',
      kind: 'PAID',
      paidAmount: '4.20',
      currency: 'USD',
      network: null,
    });
    expect(api.calls).toEqual([
      {
        path: '/v1/notifications/verify-webhook-signature',
        body: expect.objectContaining({ webhook_id: WEBHOOK_ID }),
      },
    ]);
  });

  it('refuses what PayPal did not confirm', async () => {
    const api = new FakeApi();
    api.status = 'FAILURE';

    await expect(verifier(api).verifier.verify(body(event()), HEADERS)).resolves.toBeNull();
  });

  it('refuses when the verification call itself fails', async () => {
    const api = new FakeApi();
    api.fails = true;

    await expect(verifier(api).verifier.verify(body(event()), HEADERS)).resolves.toBeNull();
  });

  it('refuses before calling PayPal when a signature header is missing', async () => {
    const { verifier: subject, api } = verifier();
    const { 'paypal-transmission-sig': _dropped, ...partial } = HEADERS;

    await expect(subject.verify(body(event()), partial)).resolves.toBeNull();
    expect(api.calls).toHaveLength(0);
  });

  it('reads a refund as a refund', async () => {
    const { verifier: subject } = verifier();
    const refunded = event({ event_type: 'PAYMENT.CAPTURE.REFUNDED' });

    await expect(subject.verify(body(refunded), HEADERS)).resolves.toMatchObject({
      kind: 'REFUNDED',
    });
  });

  it('stores a confirmed event type it does not model without acting on it', async () => {
    const { verifier: subject } = verifier();
    const other = event({ event_type: 'CHECKOUT.ORDER.APPROVED' });

    await expect(subject.verify(body(other), HEADERS)).resolves.toMatchObject({ kind: 'IGNORED' });
  });

  it('refuses an event that names no order at all', async () => {
    const { verifier: subject } = verifier();
    const orphan = event({ resource: { id: 'CAPTURE-1', amount: { value: '4.20' } } });

    await expect(subject.verify(body(orphan), HEADERS)).resolves.toBeNull();
  });
});
