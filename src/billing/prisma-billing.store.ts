import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import type { BillingStore, NewPayment, SubscriptionRow } from './billing.store';

const SUBSCRIPTION_FIELDS = {
  id: true,
  periodKey: true,
  status: true,
  startsAt: true,
  expiresAt: true,
} as const;

@Injectable()
export class PrismaBillingStore implements BillingStore {
  constructor(private readonly prisma: PrismaService) {}

  findSubscription(userId: string, periodKey: string): Promise<SubscriptionRow | null> {
    return this.prisma.subscription.findUnique({
      where: { userId_periodKey: { userId, periodKey } },
      select: SUBSCRIPTION_FIELDS,
    });
  }

  createSubscription(userId: string, periodKey: string): Promise<SubscriptionRow> {
    return this.prisma.subscription.create({
      data: { userId, periodKey },
      select: SUBSCRIPTION_FIELDS,
    });
  }

  createPayment(payment: NewPayment): Promise<{ readonly id: string }> {
    return this.prisma.payment.create({ data: { ...payment }, select: { id: true } });
  }

  latestSubscription(userId: string): Promise<SubscriptionRow | null> {
    return this.prisma.subscription.findFirst({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: SUBSCRIPTION_FIELDS,
    });
  }
}
