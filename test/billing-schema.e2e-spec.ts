import { randomBytes } from 'node:crypto';
import type { Prisma, PrismaClient } from '@prisma/client';
import { createTestPrisma, describeWithDatabase } from './db/helpers/database';

const ROLLBACK = 'billing-probe-rollback';

/**
 * Probes run as kfa_app and are always rolled back, so a row that the runtime
 * role may not delete can never leak into the next run.
 */
async function withRollback<T>(
  prisma: PrismaClient,
  probe: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  let result: T | undefined;

  try {
    await prisma.$transaction(async (tx) => {
      result = await probe(tx);
      throw new Error(ROLLBACK);
    });
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes(ROLLBACK)) {
      throw error;
    }
  }

  return result as T;
}

async function expectRejected(
  prisma: PrismaClient,
  probe: (tx: Prisma.TransactionClient) => Promise<unknown>,
): Promise<Error> {
  let rejection: unknown = null;

  await withRollback(prisma, async (tx) => {
    try {
      await probe(tx);
    } catch (error) {
      rejection = error;
    }
  });

  if (rejection === null) {
    throw new Error('expected the write to be rejected');
  }

  return rejection as Error;
}

function seedUser(tx: Prisma.TransactionClient): Promise<{ id: string }> {
  return tx.user.create({
    data: { username: `billing_${randomBytes(6).toString('hex')}` },
    select: { id: true },
  });
}

function seedSubscription(
  tx: Prisma.TransactionClient,
  userId: string,
  periodKey = '2026-Q1',
): Promise<{ id: string; status: string }> {
  return tx.subscription.create({
    data: { userId, periodKey },
    select: { id: true, status: true },
  });
}

function seedPayment(
  tx: Prisma.TransactionClient,
  subscriptionId: string,
): Promise<{ id: string }> {
  return tx.payment.create({
    data: {
      subscriptionId,
      provider: 'NOWPAYMENTS',
      providerPaymentId: `pay_${randomBytes(6).toString('hex')}`,
      expectedAmount: '25.000000',
      expectedCurrency: 'USDT',
      expectedNetwork: 'TRC20',
    },
    select: { id: true },
  });
}

describeWithDatabase('billing schema (PostgreSQL)', () => {
  let prisma: PrismaClient;

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.$disconnect();
    }
  });

  it('defaults a subscription to NONE', async () => {
    const subscription = await withRollback(prisma, async (tx) => {
      const user = await seedUser(tx);
      return seedSubscription(tx, user.id);
    });

    expect(subscription.status).toBe('NONE');
  });

  it('allows one subscription per user and period', async () => {
    const rejection = await expectRejected(prisma, async (tx) => {
      const user = await seedUser(tx);
      await seedSubscription(tx, user.id, '2026-Q1');
      await seedSubscription(tx, user.id, '2026-Q1');
    });

    expect((rejection as { code?: string }).code).toBe('P2002');
  });

  it('rejects a duplicate provider event', async () => {
    const rejection = await expectRejected(prisma, async (tx) => {
      const event = {
        provider: 'NOWPAYMENTS' as const,
        eventId: `evt_${randomBytes(6).toString('hex')}`,
        payloadHash: randomBytes(32).toString('hex'),
        signatureValid: true,
      };

      await tx.webhookEvent.create({ data: event });
      await tx.webhookEvent.create({ data: event });
    });

    expect((rejection as { code?: string }).code).toBe('P2002');
  });

  it('refuses DELETE on payments and webhook events', async () => {
    const paymentRejection = await expectRejected(prisma, async (tx) => {
      const user = await seedUser(tx);
      const subscription = await seedSubscription(tx, user.id);
      await seedPayment(tx, subscription.id);
      await tx.$executeRawUnsafe('DELETE FROM payments');
    });

    expect(paymentRejection.message).toMatch(/permission denied/i);

    const webhookRejection = await expectRejected(prisma, async (tx) => {
      await tx.$executeRawUnsafe('DELETE FROM webhook_events');
    });

    expect(webhookRejection.message).toMatch(/permission denied/i);
  });

  it('rejects a change to the expected amount', async () => {
    const rejection = await expectRejected(prisma, async (tx) => {
      const user = await seedUser(tx);
      const subscription = await seedSubscription(tx, user.id);
      const payment = await seedPayment(tx, subscription.id);

      await tx.payment.update({
        where: { id: payment.id },
        data: { expectedAmount: '250.000000' },
      });
    });

    expect(rejection.message).toMatch(/immutable/i);
  });

  it('still allows a status update', async () => {
    const payment = await withRollback(prisma, async (tx) => {
      const user = await seedUser(tx);
      const subscription = await seedSubscription(tx, user.id);
      const created = await seedPayment(tx, subscription.id);

      return tx.payment.update({
        where: { id: created.id },
        data: { status: 'CONFIRMED', confirmedAt: new Date() },
        select: { status: true },
      });
    });

    expect(payment.status).toBe('CONFIRMED');
  });
});
