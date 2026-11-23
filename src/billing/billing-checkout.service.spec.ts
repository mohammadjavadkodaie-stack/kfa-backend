import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import type { PaymentProvider, SubscriptionStatus } from '@prisma/client';
import type { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import type { Env } from '../config/env';
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

  async findActive(): Promise<BillingPlan | null> {
    return this.plan;
  }

  async setPrice(id: string, priceUsd: string): Promise<BillingPlan | null> {
    if (this.plan === null || this.plan.id !== id) return null;

    this.prices.push(priceUsd);
    this.plan = { ...this.plan, priceUsd };

    return this.plan;
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

  async record(input: Record<string, unknown>): Promise<unknown> {
    this.records.push(input);

    return {};
  }
}

function build(options: { env?: Partial<Env>; sessions?: PaymentSessionClients } = {}) {
  const plans = new FakePlans();
  const store = new FakeStore();
  const nowPayments = new FakeSession('NOWPAYMENTS');
  const paypal = new FakeSession('PAYPAL');
  const sessions =
    options.sessions ??
    new Map<PaymentProvider, PaymentSessionClient>([
      ['NOWPAYMENTS', nowPayments],
      ['PAYPAL', paypal],
    ]);
  const audit = new FakeAudit();
  const env = { BILLING_RETURN_URL: RETURN_URL, ...options.env } as unknown as Env;
  const service = new BillingCheckoutService(
    plans,
    store,
    sessions,
    env,
    audit as unknown as AuditService,
  );

  return { service, plans, store, nowPayments, paypal, audit };
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
