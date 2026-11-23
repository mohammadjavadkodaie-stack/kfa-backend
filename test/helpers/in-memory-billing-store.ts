import type { SubscriptionStatus } from '@prisma/client';
import type { BillingStore, NewPayment, SubscriptionRow } from '../../src/billing/billing.store';

/** One stored row also remembers its owner; the billing seam never returns it. */
interface StoredSubscription extends SubscriptionRow {
  readonly userId: string;
  readonly createdAt: Date;
}

/**
 * The subscription table as the review and athlete suites need it: enough of
 * the billing store to answer "what does this account have now?" without
 * PostgreSQL. A suite grants or clears a row; nothing else writes here.
 */
export class InMemoryBillingStore implements BillingStore {
  private readonly rows: StoredSubscription[] = [];
  private sequence = 0;
  readonly payments: NewPayment[] = [];

  /** Gives an account one row; the newest row is the one a read reports. */
  grant(
    userId: string,
    status: SubscriptionStatus,
    options: {
      readonly periodKey?: string;
      readonly startsAt?: Date | null;
      readonly expiresAt?: Date | null;
    } = {},
  ): SubscriptionRow {
    this.sequence += 1;

    const row: StoredSubscription = {
      id: `subscription-${this.sequence}`,
      userId,
      periodKey: options.periodKey ?? 'default',
      status,
      startsAt: options.startsAt ?? null,
      expiresAt: options.expiresAt ?? null,
      createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, this.sequence)),
    };

    this.rows.push(row);

    return row;
  }

  /** Removes every row of one account: the account has no subscription at all. */
  clear(userId: string): void {
    for (let index = this.rows.length - 1; index >= 0; index -= 1) {
      if (this.rows[index]?.userId === userId) this.rows.splice(index, 1);
    }
  }

  async findSubscription(userId: string, periodKey: string): Promise<SubscriptionRow | null> {
    return this.rows.find((row) => row.userId === userId && row.periodKey === periodKey) ?? null;
  }

  async createSubscription(userId: string, periodKey: string): Promise<SubscriptionRow> {
    return this.grant(userId, 'NONE', { periodKey });
  }

  async createPayment(payment: NewPayment): Promise<{ readonly id: string }> {
    this.payments.push(payment);

    return { id: `payment-${this.payments.length}` };
  }

  async latestSubscription(userId: string): Promise<SubscriptionRow | null> {
    return this.rows.filter((row) => row.userId === userId).at(-1) ?? null;
  }
}
