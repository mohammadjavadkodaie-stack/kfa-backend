import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import type { PaymentProvider, Prisma, SubscriptionStatus } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import type { Env } from '../config/env';
import type { PrismaService } from '../database/prisma.service';
import { BillingCheckoutService } from './billing-checkout.service';
import type { BillingPlan, BillingPlanRepository } from './billing-plan';
import type { BillingStore, NewPayment, SubscriptionRow } from './billing.store';
import type {
  CheckoutRequest,
  CheckoutSession,
  PaymentSessionClient,
  PaymentSessionClients,
} from './payment-session';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const ACTOR: PolicySubject = { id: USER_ID, role: Role.ATHLETE };
const REQUEST_ID = 'request-1';
const RETURN_URL = 'https://kfa.example/account/subscription/return';

const PLAN: BillingPlan = {
  id: 'plan-1',
  code: 'standard',
  periodKey: 'default',
  priceUsd: '4.20',
  periodDays: 365,
};

class FakePlans implements BillingPlanRepository {
  plan: BillingPlan | null = PLAN;
  readonly prices: string[] = [];
  /** The client each write was asked to join; `undefined` when the call had none. */
  readonly txArgs: (Prisma.TransactionClient | undefined)[] = [];

  async findActive(): Promise<BillingPlan | null> {
    return this.plan;
  }

  /** A compare-and-set, like the row: a write from anything but the stored amount loses. */
  async setPrice(
    id: string,
    fromPriceUsd: string,
    priceUsd: string,
    tx?: Prisma.TransactionClient,
  ): Promise<BillingPlan | null> {
    this.txArgs.push(tx);

    if (this.plan === null || this.plan.id !== id || this.plan.priceUsd !== fromPriceUsd) {
      return null;
    }

    this.prices.push(priceUsd);
    this.plan = { ...this.plan, priceUsd };

    return this.plan;
  }
}

/** Another staff member changes the amount between the read and the write. */
class RacingPlans extends FakePlans {
  override async findActive(): Promise<BillingPlan | null> {
    const plan = await super.findActive();

    if (plan !== null) this.plan = { ...plan, priceUsd: '4.30' };

    return plan;
  }
}

class FakeStore implements BillingStore {
  readonly subscriptions: SubscriptionRow[] = [];
  readonly payments: NewPayment[] = [];

  async findSubscription(_userId: string, periodKey: string): Promise<SubscriptionRow | null> {
    return this.subscriptions.find((row) => row.periodKey === periodKey) ?? null;
  }

  async createSubscription(_userId: string, periodKey: string): Promise<SubscriptionRow> {
    const row: SubscriptionRow = {
      id: `sub-${this.subscriptions.length + 1}`,
      periodKey,
      status: 'NONE',
      startsAt: null,
      expiresAt: null,
    };
    this.subscriptions.push(row);

    return row;
  }

  async createPayment(payment: NewPayment): Promise<{ readonly id: string }> {
    this.payments.push(payment);

    return { id: `payment-${this.payments.length}` };
  }

  async latestSubscription(_userId: string): Promise<SubscriptionRow | null> {
    return this.subscriptions.at(-1) ?? null;
  }
}

class FakeSession implements PaymentSessionClient {
  readonly requests: CheckoutRequest[] = [];

  constructor(readonly provider: PaymentProvider) {}

  async createCheckout(request: CheckoutRequest): Promise<CheckoutSession> {
    this.requests.push(request);

    return { providerPaymentId: `session-${this.provider}`, redirectUrl: 'https://pay.example/1' };
  }
}

class FakeAudit {
  readonly records: Record<string, unknown>[] = [];
  /** The client each row was asked to join; `undefined` when the call had none. */
  readonly transactions: unknown[] = [];

  async record(input: Record<string, unknown>, tx?: unknown): Promise<unknown> {
    this.records.push(input);
    this.transactions.push(tx);

    return {};
  }
}

/** An audit trail that cannot be written: the price change must fail with it. */
class FailingAudit extends FakeAudit {
  override async record(input: Record<string, unknown>, tx?: unknown): Promise<unknown> {
    await super.record(input, tx);

    throw new Error('audit chain is unavailable');
  }
}

/** Keeps what the failure path logged, so a silent rollback cannot pass. */
class RecordingLogger {
  readonly warns: Record<string, unknown>[] = [];

  warn(payload: Record<string, unknown>): void {
    this.warns.push(payload);
  }
}

/**
 * Stands in for `PrismaService`: one transaction, undone when the callback
 * throws - the in-process equivalent of the rollback the real client performs.
 * `client` is what the callback receives, and what the price write and the audit
 * row must both name to prove they shared one transaction.
 */
class FakePrisma {
  readonly client = { transaction: 'fake' } as unknown as Prisma.TransactionClient;
  /** The options each transaction was opened with; bounded, like the app's own. */
  readonly options: unknown[] = [];
  transactions = 0;

  constructor(private readonly plans: FakePlans) {}

  async $transaction<T>(
    work: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    const plan = this.plans.plan === null ? null : { ...this.plans.plan };

    this.transactions += 1;
    this.options.push(options);

    try {
      return await work(this.client);
    } catch (error) {
      // The row written inside the failed transaction never existed.
      this.plans.plan = plan;

      throw error;
    }
  }
}

function build(
  options: {
    env?: Partial<Env>;
    sessions?: PaymentSessionClients;
    audit?: FakeAudit;
    plans?: FakePlans;
  } = {},
) {
  const plans = options.plans ?? new FakePlans();
  const store = new FakeStore();
  const nowPayments = new FakeSession('NOWPAYMENTS');
  const paypal = new FakeSession('PAYPAL');
  const sessions =
    options.sessions ??
    new Map<PaymentProvider, PaymentSessionClient>([
      ['NOWPAYMENTS', nowPayments],
      ['PAYPAL', paypal],
    ]);
  const audit = options.audit ?? new FakeAudit();
  const logger = new RecordingLogger();
  const prisma = new FakePrisma(plans);
  const env = { BILLING_RETURN_URL: RETURN_URL, ...options.env } as unknown as Env;
  const service = new BillingCheckoutService(
    plans,
    store,
    sessions,
    env,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    prisma as unknown as PrismaService,
  );

  return { service, plans, store, nowPayments, paypal, audit, logger, prisma };
}

function withStatus(status: SubscriptionStatus, expiresAt: Date | null = null): SubscriptionRow {
  return { id: 'sub-1', periodKey: 'default', status, startsAt: null, expiresAt };
}

describe('BillingCheckoutService', () => {
  it('starts a USDT TRC20 payment for the stored price', async () => {
    const { service, store, nowPayments } = build();

    const view = await service.checkout(ACTOR, 'NOWPAYMENTS', REQUEST_ID);

    expect(view).toEqual({ redirectUrl: 'https://pay.example/1', paymentId: 'payment-1' });
    expect(store.payments[0]).toMatchObject({
      provider: 'NOWPAYMENTS',
      providerPaymentId: 'session-NOWPAYMENTS',
      expectedAmount: '4.20',
      expectedCurrency: 'USDT',
      expectedNetwork: 'TRC20',
    });
    expect(nowPayments.requests[0]).toMatchObject({
      amount: '4.20',
      currency: 'USDT',
      returnUrl: RETURN_URL,
    });
  });

  it('starts a USD payment for PayPal, with no network', async () => {
    const { service, store, paypal } = build();

    await service.checkout(ACTOR, 'PAYPAL', REQUEST_ID);

    expect(store.payments[0]).toMatchObject({ expectedCurrency: 'USD', expectedNetwork: null });
    expect(paypal.requests).toHaveLength(1);
  });

  it('keeps one subscription row per period across attempts', async () => {
    const { service, store } = build();

    await service.checkout(ACTOR, 'NOWPAYMENTS', REQUEST_ID);
    await service.checkout(ACTOR, 'PAYPAL', REQUEST_ID);

    expect(store.subscriptions).toHaveLength(1);
    expect(store.payments).toHaveLength(2);
  });

  it('refuses a second payment while the period is already covered', async () => {
    const { service, store, nowPayments } = build();
    store.subscriptions.push(withStatus('ACTIVE', new Date(Date.now() + 86_400_000)));

    await expect(service.checkout(ACTOR, 'NOWPAYMENTS', REQUEST_ID)).rejects.toBeInstanceOf(
      ConflictException,
    );
    expect(nowPayments.requests).toHaveLength(0);
  });

  it('refuses to sell when the provider is not configured', async () => {
    const { service } = build({ sessions: new Map() });

    await expect(service.checkout(ACTOR, 'NOWPAYMENTS', REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('refuses to sell without a return address', async () => {
    const { service } = build({ env: { BILLING_RETURN_URL: undefined } });

    await expect(service.checkout(ACTOR, 'NOWPAYMENTS', REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('refuses when the catalogue is empty', async () => {
    const { service, plans } = build();
    plans.plan = null;

    await expect(service.catalogue()).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  describe('changePrice', () => {
    it('records the price change with both amounts', async () => {
      const { service, plans, audit } = build();

      const view = await service.changePrice({ id: USER_ID, role: Role.OWNER }, '4.50', REQUEST_ID);

      expect(view.priceUsd).toBe('4.50');
      expect(plans.prices).toEqual(['4.50']);
      expect(audit.records[0]).toMatchObject({
        action: 'billing.price.changed',
        actorRole: Role.OWNER,
        metadata: { from: '4.20', to: '4.50' },
      });
      // Exactly the two amounts: no extra field reaches the chain.
      expect(audit.records[0]?.metadata).toEqual({ from: '4.20', to: '4.50' });
    });

    it('writes the price and its audit row in one transaction', async () => {
      const { service, plans, audit, prisma } = build();

      await service.changePrice({ id: USER_ID, role: Role.ADMIN }, '4.50', REQUEST_ID);

      expect(prisma.transactions).toBe(1);
      // The write itself joined the transaction: the repository saw its client.
      expect(plans.txArgs).toEqual([prisma.client]);
      // And so did the row, instead of opening a transaction of its own.
      expect(audit.transactions).toEqual([prisma.client]);
      // Bounded, so a held lock fails the request instead of hanging it.
      expect(prisma.options).toEqual([{ maxWait: 5_000, timeout: 10_000 }]);
      expect(plans.plan?.priceUsd).toBe('4.50');
    });

    it('rolls the price back when the audit row cannot be written', async () => {
      const { service, plans, audit, prisma, logger } = build({ audit: new FailingAudit() });

      await expect(
        service.changePrice({ id: USER_ID, role: Role.OWNER }, '4.50', REQUEST_ID),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      expect(prisma.transactions).toBe(1);
      // The row was attempted inside the change's own transaction...
      expect(audit.transactions).toEqual([prisma.client]);
      // ...and the amount it describes is still the stored one.
      expect(plans.plan?.priceUsd).toBe('4.20');
      expect(logger.warns).toEqual([{ requestId: REQUEST_ID, action: 'billing.price.changed' }]);
    });

    it('refuses a change that lost the race instead of recording a stale from', async () => {
      const { service, plans, audit, prisma } = build({ plans: new RacingPlans() });

      await expect(
        service.changePrice({ id: USER_ID, role: Role.OWNER }, '4.50', REQUEST_ID),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      expect(prisma.transactions).toBe(1);
      expect(audit.records).toHaveLength(0);
      expect(plans.plan?.priceUsd).toBe('4.30');
    });

    it('opens no transaction when there is no active offer', async () => {
      const { service, plans, audit, prisma } = build();
      plans.plan = null;

      await expect(
        service.changePrice({ id: USER_ID, role: Role.OWNER }, '4.50', REQUEST_ID),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      expect(prisma.transactions).toBe(0);
      expect(audit.records).toHaveLength(0);
    });
  });

  it('reads a subscription that ran out as expired without writing it', async () => {
    const { service, store } = build();
    store.subscriptions.push(withStatus('ACTIVE', new Date(Date.now() - 1_000)));

    await expect(service.subscription(USER_ID)).resolves.toMatchObject({ status: 'EXPIRED' });
    expect(store.subscriptions[0]?.status).toBe('ACTIVE');
  });

  it('reads a missing subscription as none, with the offer beside it', async () => {
    const { service } = build();

    await expect(service.subscription(USER_ID)).resolves.toEqual({
      status: 'NONE',
      periodKey: 'default',
      startsAt: null,
      expiresAt: null,
      priceUsd: '4.20',
      periodDays: 365,
    });
  });
});
