import request from 'supertest';
import type { WebhookVerifiers } from '../src/billing/billing-webhook.service';
import type {
  NormalizedEvent,
  Verification,
  WebhookVerifier,
} from '../src/billing/webhook-verifier';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

const PAYLOAD = '{"payment_id":"p-1","payment_status":"finished"}';
const PROVIDER = 'NOWPAYMENTS';
const ROUTE = '/billing/webhook';

class RecordingVerifier implements WebhookVerifier {
  readonly provider = PROVIDER;
  outcome: 'event' | 'unavailable' = 'event';
  readonly bodies: Buffer[] = [];
  event: NormalizedEvent = {
    eventId: 'evt-1',
    providerPaymentId: 'p-1',
    kind: 'PAID',
    paidAmount: '25',
    currency: 'USDT',
    network: 'TRC20',
  };

  async verify(rawBody: Buffer): Promise<Verification> {
    this.bodies.push(rawBody);

    return this.outcome === 'unavailable'
      ? { status: 'unavailable' }
      : { status: 'event', event: this.event };
  }
}

function rateLimit(allowed: boolean): RateLimitService {
  return {
    consume: async (): Promise<RateLimitDecision> => ({
      allowed,
      remaining: allowed ? 1 : 0,
      retryAfterSeconds: allowed ? 0 : 30,
    }),
  } as unknown as RateLimitService;
}

/**
 * The service's transaction only has to say "already seen": nothing is written
 * and no audit runs, so what this suite exercises is the route itself (raw
 * bytes, status codes, envelopes) rather than the billing state machine.
 */
const NO_WRITES = {
  $connect: (): Promise<void> => Promise.resolve(),
  $disconnect: (): Promise<void> => Promise.resolve(),
  $transaction: (run: (tx: unknown) => Promise<unknown>): Promise<unknown> =>
    run({ webhookEvent: { createMany: async () => ({ count: 0 }) } }),
};

function verifiers(verifier: WebhookVerifier): WebhookVerifiers {
  return new Map([[PROVIDER, verifier]]);
}

describe('billing webhook route (e2e)', () => {
  it('answers 404 for a provider with no verifier', async () => {
    const app = await createTestApp({}, { rateLimit: rateLimit(true) });

    try {
      const response = await request(app.getHttpServer())
        .post(`${ROUTE}/${PROVIDER.toLowerCase()}`)
        .set('content-type', 'application/json')
        .send(PAYLOAD);

      expect(response.status).toBe(404);
      expect(response.body).toMatchObject({ statusCode: 404 });
    } finally {
      await app.close();
    }
  });

  it('hands the exact bytes to the verifier and accepts the delivery', async () => {
    const sources = new RecordingVerifier();
    const app = await createTestApp(
      {},
      { prisma: NO_WRITES, rateLimit: rateLimit(true), webhookVerifiers: verifiers(sources) },
    );

    try {
      const response = await request(app.getHttpServer())
        .post(`${ROUTE}/${PROVIDER.toLowerCase()}`)
        .set('content-type', 'application/json')
        .send(PAYLOAD);

      expect(response.status).toBe(202);
      expect(response.body).toEqual({ accepted: true });
      expect(sources.bodies).toHaveLength(1);
      expect(sources.bodies[0]?.toString('utf8')).toBe(PAYLOAD);
    } finally {
      await app.close();
    }
  });

  it('answers 400 for a body that is not JSON', async () => {
    const sources = new RecordingVerifier();
    const app = await createTestApp(
      {},
      { prisma: NO_WRITES, rateLimit: rateLimit(true), webhookVerifiers: verifiers(sources) },
    );

    try {
      const response = await request(app.getHttpServer())
        .post(`${ROUTE}/${PROVIDER.toLowerCase()}`)
        .set('content-type', 'text/plain')
        .send('payment_id=p-1');

      expect(response.status).toBe(400);
      expect(sources.bodies).toHaveLength(0);
    } finally {
      await app.close();
    }
  });

  it('asks the provider to retry when the verifier cannot decide', async () => {
    const sources = new RecordingVerifier();
    sources.outcome = 'unavailable';
    const app = await createTestApp(
      {},
      { prisma: NO_WRITES, rateLimit: rateLimit(true), webhookVerifiers: verifiers(sources) },
    );

    try {
      const response = await request(app.getHttpServer())
        .post(`${ROUTE}/${PROVIDER.toLowerCase()}`)
        .set('content-type', 'application/json')
        .send(PAYLOAD);

      expect(response.status).toBe(503);
      expect(response.body).toMatchObject({ statusCode: 503 });
    } finally {
      await app.close();
    }
  });

  it('answers 429 with the shared envelope when the address is over budget', async () => {
    const app = await createTestApp(
      {},
      {
        prisma: NO_WRITES,
        rateLimit: rateLimit(false),
        webhookVerifiers: verifiers(new RecordingVerifier()),
      },
    );

    try {
      const response = await request(app.getHttpServer())
        .post(`${ROUTE}/${PROVIDER.toLowerCase()}`)
        .set('content-type', 'application/json')
        .send(PAYLOAD);

      expect(response.status).toBe(429);
      expect(response.headers['retry-after']).toBe('30');
      expect(response.body).toMatchObject({ statusCode: 429 });
    } finally {
      await app.close();
    }
  });
});
