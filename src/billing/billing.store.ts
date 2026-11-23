import type { PaymentProvider, SubscriptionStatus } from '@prisma/client';

/** The part of a subscription the billing flow reads or writes. */
export interface SubscriptionRow {
  readonly id: string;
  readonly periodKey: string;
  readonly status: SubscriptionStatus;
  readonly startsAt: Date | null;
  readonly expiresAt: Date | null;
}

/** One payment row, at the moment the checkout creates it. */
export interface NewPayment {
  readonly subscriptionId: string;
  readonly provider: PaymentProvider;
  readonly providerPaymentId: string;
  readonly expectedAmount: string;
  readonly expectedCurrency: string;
  readonly expectedNetwork: string | null;
}

/**
 * The billing writes the checkout needs.
 *
 * A seam rather than direct Prisma calls: the flow (which row is created, with
 * which amount, in which order) is what the tests have to prove, and that must
 * not need a database.
 */
export interface BillingStore {
  findSubscription(userId: string, periodKey: string): Promise<SubscriptionRow | null>;
  createSubscription(userId: string, periodKey: string): Promise<SubscriptionRow>;
  createPayment(payment: NewPayment): Promise<{ readonly id: string }>;
  latestSubscription(userId: string): Promise<SubscriptionRow | null>;
}
