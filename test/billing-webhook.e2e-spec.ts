import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { BillingWebhookService } from '../src/billing/billing-webhook.service';
import type {
  NormalizedEvent,
  Verification,
  WebhookVerifier,
} from '../src/billing/webhook-verifier';
import {
  createTestAuditService,
  createTestPrisma,
  describeWithDatabase,
} from './db/helpers/database';

type Event = NormalizedEvent & { valid?: boolean };

class FakeVerifier implements WebhookVerifier {
  readonly provider = 'NOWPAYMENTS';
  constructor(private readonly events: Map<string, Event>) {}
  async verify(
    _rawBody: Buffer,
    headers: Record<string, string | string[] | undefined>,
  ): Promise<Verification> {
    const event = this.events.get(String(headers.event));

    if (event === undefined || event.valid === false) return { status: 'invalid' };

    return { status: 'event', event };
  }
}

const id = (prefix: string) => `${prefix}_${randomBytes(6).toString('hex')}`;

describeWithDatabase('billing webhooks', () => {
  let prisma: PrismaClient;
  let service: BillingWebhookService;
  const events = new Map<string, Event>();
  const provider = 'NOWPAYMENTS';

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    service = new BillingWebhookService(
      prisma as never,
      createTestAuditService(prisma),
      new Map([[provider, new FakeVerifier(events)]]),
    );
  });
  afterAll(async () => prisma?.$disconnect());

  async function seed() {
    const user = await prisma.user.create({
      data: { username: id('wh_user') },
      select: { id: true },
    });
    const subscription = await prisma.subscription.create({
      data: { userId: user.id, periodKey: id('period') },
      select: { id: true },
    });
    const payment = await prisma.payment.create({
      data: {
        subscriptionId: subscription.id,
        provider,
        providerPaymentId: id('payment'),
        expectedAmount: '25',
        expectedCurrency: 'USDT',
        expectedNetwork: 'TRC20',
      },
      select: { id: true, providerPaymentId: true },
    });
    return { subscription, payment };
  }
  async function send(event: Event, header = event.eventId) {
    events.set(event.eventId, event);
    return service.handle(provider, Buffer.from(event.eventId), { event: header });
  }
  function paid(paymentId: string, eventId = id('event'), extra: Partial<Event> = {}): Event {
    return {
      eventId,
      providerPaymentId: paymentId,
      kind: 'PAID',
      paidAmount: '25',
      currency: 'USDT',
      network: 'TRC20',
      ...extra,
    };
  }

  it('rejects forged signatures', async () => {
    const seeded = await seed();
    const event = paid(seeded.payment.providerPaymentId);
    event.valid = false;
    expect((await send(event)).accepted).toBe(false);
    // Scoped to this event: earlier runs may leave rows behind, because the
    // runtime role cannot delete from webhook_events.
    expect(await prisma.webhookEvent.count({ where: { eventId: event.eventId } })).toBe(0);
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).toBe('NONE');
  });
  it('activates paid payment', async () => {
    const seeded = await seed();
    await send(paid(seeded.payment.providerPaymentId));
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).toBe('ACTIVE');
    expect((await prisma.payment.findUnique({ where: { id: seeded.payment.id } }))?.status).toBe(
      'CONFIRMED',
    );
  });
  it('deduplicates delivery', async () => {
    const seeded = await seed();
    const event = paid(seeded.payment.providerPaymentId);
    await send(event);
    await send(event);
    expect(await prisma.webhookEvent.count({ where: { eventId: event.eventId } })).toBe(1);
  });
  it('deduplicates concurrent delivery', async () => {
    const seeded = await seed();
    const event = paid(seeded.payment.providerPaymentId);
    await Promise.all([send(event), send(event)]);
    expect(await prisma.webhookEvent.count({ where: { eventId: event.eventId } })).toBe(1);
  });
  it.each([
    ['underpaid', { paidAmount: '24' }],
    ['wrong currency', { currency: 'BTC' }],
    ['wrong network', { network: 'ERC20' }],
  ])('%s', async (_name, extra) => {
    const seeded = await seed();
    const event = paid(seeded.payment.providerPaymentId, id('event'), extra);
    await send(event);
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).not.toBe('ACTIVE');
    expect(
      (
        await prisma.webhookEvent.findUnique({
          where: { provider_eventId: { provider, eventId: event.eventId } },
        })
      )?.outcome,
    ).toBe('amount_mismatch');
  });
  it('accepts unknown payment', async () => {
    const event = paid(id('missing'));
    expect((await send(event)).accepted).toBe(true);
    expect(
      (
        await prisma.webhookEvent.findUnique({
          where: { provider_eventId: { provider, eventId: event.eventId } },
        })
      )?.outcome,
    ).toBe('unknown_payment');
  });
  it('does not reactivate refunded payment', async () => {
    const seeded = await seed();
    await prisma.payment.update({ where: { id: seeded.payment.id }, data: { status: 'REFUNDED' } });
    await prisma.subscription.update({
      where: { id: seeded.subscription.id },
      data: { status: 'REFUNDED' },
    });
    await send(paid(seeded.payment.providerPaymentId));
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).toBe('REFUNDED');
  });
  it('refunds after paid', async () => {
    const seeded = await seed();
    await send(paid(seeded.payment.providerPaymentId));
    await send({
      eventId: id('refund'),
      providerPaymentId: seeded.payment.providerPaymentId,
      kind: 'REFUNDED',
    });
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).toBe('REFUNDED');
  });
  it('moves pending to paid', async () => {
    const seeded = await seed();
    await send({
      eventId: id('pending'),
      providerPaymentId: seeded.payment.providerPaymentId,
      kind: 'PENDING',
    });
    await send(paid(seeded.payment.providerPaymentId));
    expect(
      (await prisma.subscription.findUnique({ where: { id: seeded.subscription.id } }))?.status,
    ).toBe('ACTIVE');
  });
});
