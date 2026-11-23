import { Inject, Injectable } from '@nestjs/common';
import type { SubscriptionStatus } from '@prisma/client';
import { BILLING_STORE } from './billing.tokens';
import type { BillingStore, SubscriptionRow } from './billing.store';

/**
 * A subscription that ran out reads as EXPIRED; the stored column is changed by
 * a provider event only, never by a read.
 */
export function effectiveSubscriptionStatus(
  row: SubscriptionRow,
  now: Date = new Date(),
): SubscriptionStatus {
  if (
    row.status === 'ACTIVE' &&
    row.expiresAt !== null &&
    row.expiresAt.getTime() <= now.getTime()
  ) {
    return 'EXPIRED';
  }

  return row.status;
}

/**
 * One answer to "what does this account have now?" for every module that needs
 * it - the athlete's own read, the staff queue and the approval gate - so the
 * EXPIRED rule and "no row means NONE" live in exactly one place.
 */
@Injectable()
export class SubscriptionStatusService {
  constructor(@Inject(BILLING_STORE) private readonly store: BillingStore) {}

  async statusOf(userId: string): Promise<SubscriptionStatus> {
    const row = await this.store.latestSubscription(userId);

    return row === null ? 'NONE' : effectiveSubscriptionStatus(row);
  }

  /** Only ACTIVE is paid: PENDING has not paid yet and EXPIRED has run out. */
  async isActive(userId: string): Promise<boolean> {
    return (await this.statusOf(userId)) === 'ACTIVE';
  }

  /**
   * The same rule for a whole queue page, in one round trip per row: the page
   * size caps it and the store stays a single-row seam.
   */
  async statusesOf(userIds: readonly string[]): Promise<ReadonlyMap<string, SubscriptionStatus>> {
    const unique = [...new Set(userIds)];
    const entries = await Promise.all(
      unique.map(async (userId) => [userId, await this.statusOf(userId)] as const),
    );

    return new Map(entries);
  }
}
