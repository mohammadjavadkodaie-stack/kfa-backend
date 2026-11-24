import { Injectable } from '@nestjs/common';
import type { BillingPlan as BillingPlanRow, Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import type { BillingPlan, BillingPlanRepository } from './billing-plan';

/** Two fraction digits: what the site shows and what the payment expects. */
function toPlan(row: BillingPlanRow): BillingPlan {
  return {
    id: row.id,
    code: row.code,
    periodKey: row.periodKey,
    priceUsd: row.priceUsd.toFixed(2),
    periodDays: row.periodDays,
  };
}

@Injectable()
export class PrismaBillingPlanRepository implements BillingPlanRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findActive(): Promise<BillingPlan | null> {
    const row = await this.prisma.billingPlan.findFirst({
      where: { active: true },
      orderBy: { createdAt: 'asc' },
    });

    return row === null ? null : toPlan(row);
  }

  /**
   * The price is written once here and frozen for every payment already issued:
   * each payment row keeps its own expected amount, so changing the offer never
   * rewrites the terms of a payment in flight.
   *
   * The where clause carries the amount the caller read, so a change that lost a
   * race writes nothing instead of overwriting a value it never described. The
   * caller's transaction, when given, is the client used for both statements.
   */
  async setPrice(
    id: string,
    fromPriceUsd: string,
    priceUsd: string,
    tx?: Prisma.TransactionClient,
  ): Promise<BillingPlan | null> {
    const client = tx ?? this.prisma;

    const updated = await client.billingPlan.updateMany({
      where: { id, active: true, priceUsd: fromPriceUsd },
      data: { priceUsd },
    });

    if (updated.count === 0) return null;

    const row = await client.billingPlan.findUnique({ where: { id } });

    return row === null ? null : toPlan(row);
  }
}
