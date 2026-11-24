import type { Prisma } from '@prisma/client';

/**
 * One priced offer. The amount is a decimal string the whole way through: money
 * never becomes a JavaScript number, so `4.20` cannot silently become
 * `4.200000000000001`.
 */
export interface BillingPlan {
  readonly id: string;
  readonly code: string;
  /** The competition period this offer belongs to; one subscription per period. */
  readonly periodKey: string;
  readonly priceUsd: string;
  readonly periodDays: number;
}

export interface BillingPlanRepository {
  /** The active offer, or null when the catalogue is empty. */
  findActive(): Promise<BillingPlan | null>;
  /**
   * A compare-and-set on that offer: the new amount is written only while the
   * stored one is still `fromPriceUsd`, so two simultaneous changes cannot both
   * be recorded as coming from the same price. Null when the offer is not active
   * any more or another change got there first.
   *
   * A caller that owns a transaction passes it as `tx`, so the write joins that
   * transaction: the price commits or rolls back with the audit row that
   * describes it.
   */
  setPrice(
    id: string,
    fromPriceUsd: string,
    priceUsd: string,
    tx?: Prisma.TransactionClient,
  ): Promise<BillingPlan | null>;
}

/** `4.2`, `4.20`, `12`, `999.99`: positive, at most two fraction digits. */
export const PRICE_USD_PATTERN = /^(?:[1-9]\d{0,3})(?:\.\d{1,2})?$/;

/** What each provider charges in, and the network it settles on. */
export function chargeFor(provider: 'NOWPAYMENTS' | 'PAYPAL'): {
  readonly currency: string;
  readonly network: string | null;
} {
  return provider === 'NOWPAYMENTS'
    ? { currency: 'USDT', network: 'TRC20' }
    : { currency: 'USD', network: null };
}
