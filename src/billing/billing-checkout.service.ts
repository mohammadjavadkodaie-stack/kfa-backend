import { ConflictException, Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { PaymentProvider, SubscriptionStatus } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { chargeFor, type BillingPlan, type BillingPlanRepository } from './billing-plan';
import { BILLING_PLAN_REPOSITORY, BILLING_STORE, PAYMENT_SESSION_CLIENTS } from './billing.tokens';
import type { BillingStore, SubscriptionRow } from './billing.store';
import type { PaymentSessionClients } from './payment-session';
import { effectiveSubscriptionStatus } from './subscription-status.service';

/** One row of the price list, exactly as the site shows it. */
export interface PlanView {
  readonly code: string;
  readonly priceUsd: string;
  readonly periodKey: string;
  readonly periodDays: number;
}

export interface SubscriptionView {
  readonly status: SubscriptionStatus;
  readonly periodKey: string | null;
  readonly startsAt: string | null;
  readonly expiresAt: string | null;
  readonly priceUsd: string | null;
  readonly periodDays: number | null;
}

export interface CheckoutView {
  readonly redirectUrl: string;
  readonly paymentId: string;
}

/**
 * The buying side of billing: what the offer costs, what the athlete already
 * has, and how a checkout starts.
 *
 * Nothing here trusts a client: the amount comes from the stored offer, the
 * currency and network from the provider, and the payment row is written with
 * those values before the provider is asked for nothing more than a page. The
 * webhook is what later decides whether money arrived.
 */
@Injectable()
export class BillingCheckoutService {
  constructor(
    @Inject(BILLING_PLAN_REPOSITORY) private readonly plans: BillingPlanRepository,
    @Inject(BILLING_STORE) private readonly store: BillingStore,
    @Inject(PAYMENT_SESSION_CLIENTS) private readonly sessions: PaymentSessionClients,
    @Inject(ENV) private readonly env: Env,
    private readonly audit: AuditService,
  ) {}

  /** The catalogue. An empty catalogue is a refusal, never a free subscription. */
  async catalogue(): Promise<PlanView[]> {
    return [toPlanView(await this.requirePlan())];
  }

  /**
   * What this athlete has now. A subscription that ran out is reported as
   * EXPIRED without writing anything: the stored status is only changed by a
   * provider event, and a read must not pretend to be one.
   */
  async subscription(userId: string): Promise<SubscriptionView> {
    const plan = await this.plans.findActive();
    const row = await this.store.latestSubscription(userId);

    if (row === null) {
      return {
        status: 'NONE',
        periodKey: plan?.periodKey ?? null,
        startsAt: null,
        expiresAt: null,
        priceUsd: plan?.priceUsd ?? null,
        periodDays: plan?.periodDays ?? null,
      };
    }

    return {
      status: effectiveSubscriptionStatus(row),
      periodKey: row.periodKey,
      startsAt: row.startsAt?.toISOString() ?? null,
      expiresAt: row.expiresAt?.toISOString() ?? null,
      priceUsd: plan?.priceUsd ?? null,
      periodDays: plan?.periodDays ?? null,
    };
  }

  async checkout(
    actor: PolicySubject,
    provider: PaymentProvider,
    requestId: string,
  ): Promise<CheckoutView> {
    const plan = await this.requirePlan();
    const client = this.sessions.get(provider);
    const returnUrl = this.env.BILLING_RETURN_URL;

    // No client or no return address means this deployment cannot sell: a
    // generic 503, and nothing is written.
    if (client === undefined || returnUrl === undefined) throw new ServiceUnavailableException();

    const { currency, network } = chargeFor(provider);
    const subscription = await this.subscriptionForPeriod(actor.id, plan.periodKey);

    // Already covered for this period: a second payment would buy nothing.
    if (effectiveSubscriptionStatus(subscription) === 'ACTIVE') throw new ConflictException();

    // Opaque and unique per attempt, so a delivery can be traced back to it.
    const reference = randomBytes(16).toString('hex');
    const session = await client.createCheckout({
      reference,
      amount: plan.priceUsd,
      currency,
      returnUrl,
    });

    const payment = await this.store.createPayment({
      subscriptionId: subscription.id,
      provider,
      providerPaymentId: session.providerPaymentId,
      expectedAmount: plan.priceUsd,
      expectedCurrency: currency,
      expectedNetwork: network,
    });

    await this.audit.record({
      action: 'billing.checkout.created',
      actorId: actor.id,
      actorRole: actor.role,
      targetType: 'payment',
      targetId: payment.id,
      requestId,
      metadata: { provider, reference, amount: plan.priceUsd, currency },
    });

    return { redirectUrl: session.redirectUrl, paymentId: payment.id };
  }

  /**
   * The owner's (or an admin's) price change. The previous and the new amount go
   * into the audit chain, and every payment already issued keeps the amount it
   * was created with.
   */
  async changePrice(actor: PolicySubject, priceUsd: string, requestId: string): Promise<PlanView> {
    const plan = await this.requirePlan();
    const updated = await this.plans.setPrice(plan.id, priceUsd);

    if (updated === null) throw new ServiceUnavailableException();

    await this.audit.record({
      action: 'billing.price.changed',
      actorId: actor.id,
      actorRole: actor.role,
      targetType: 'billing-plan',
      targetId: updated.code,
      requestId,
      metadata: { from: plan.priceUsd, to: updated.priceUsd },
    });

    return toPlanView(updated);
  }

  /** One subscription per user and period; the row exists before the payment. */
  private async subscriptionForPeriod(userId: string, periodKey: string): Promise<SubscriptionRow> {
    const existing = await this.store.findSubscription(userId, periodKey);

    return existing ?? this.store.createSubscription(userId, periodKey);
  }

  private async requirePlan(): Promise<BillingPlan> {
    const plan = await this.plans.findActive();

    if (plan === null) throw new ServiceUnavailableException();

    return plan;
  }
}

function toPlanView(plan: BillingPlan): PlanView {
  return {
    code: plan.code,
    priceUsd: plan.priceUsd,
    periodKey: plan.periodKey,
    periodDays: plan.periodDays,
  };
}
