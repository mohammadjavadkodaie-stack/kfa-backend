import { BadRequestException, ValidationPipe } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../audit/audit.service';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { Role } from '../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import type { Env } from '../config/env';
import type { PrismaService } from '../database/prisma.service';
import type { RateLimitService } from '../rate-limit/rate-limit.service';
import { BillingCheckoutService } from './billing-checkout.service';
import type { BillingPlan, BillingPlanRepository } from './billing-plan';
import type { BillingStore } from './billing.store';
import { BillingController, PriceDto } from './billing.controller';
import type { PaymentSessionClients } from './payment-session';

/**
 * The price route at the controller seam: what the decorators declare, and what
 * the global validation pipe refuses before the service - and therefore the
 * transaction and the audit row - is reached.
 *
 * The guards themselves are global and covered by the route-marker sweep; the
 * point here is that this route cannot lose its role or step-up marker, and that
 * an amount outside the rule opens no transaction and writes no audit row.
 */

const ACTOR_ID = '11111111-1111-4111-8111-111111111111';
const REQUEST_ID = 'req-price';

const PLAN: BillingPlan = {
  id: 'plan-1',
  code: 'standard',
  periodKey: 'default',
  priceUsd: '4.20',
  periodDays: 365,
};

const request = {
  auth: { userId: ACTOR_ID, role: Role.OWNER },
  id: REQUEST_ID,
} as unknown as AuthenticatedRequest;

class FakePlans implements BillingPlanRepository {
  async findActive(): Promise<BillingPlan> {
    return PLAN;
  }

  async setPrice(_id: string, _fromPriceUsd: string, priceUsd: string): Promise<BillingPlan> {
    return { ...PLAN, priceUsd };
  }
}

class FakeAudit {
  readonly records: unknown[] = [];
  readonly transactions: unknown[] = [];

  async record(entry: unknown, tx?: unknown): Promise<void> {
    this.records.push(entry);
    this.transactions.push(tx);
  }
}

/** Counts transactions and passes the callback the client it would really see. */
class FakePrisma {
  readonly client = { transaction: 'fake' } as unknown as Prisma.TransactionClient;
  transactions = 0;

  async $transaction<T>(work: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    this.transactions += 1;

    return work(this.client);
  }
}

function build() {
  const audit = new FakeAudit();
  const prisma = new FakePrisma();
  const service = new BillingCheckoutService(
    new FakePlans(),
    {} as BillingStore,
    new Map() as PaymentSessionClients,
    {} as Env,
    audit as unknown as AuditService,
    { warn: (): void => undefined } as unknown as PinoLogger,
    prisma as unknown as PrismaService,
  );
  const controller = new BillingController(service, {} as RateLimitService);

  return { controller, audit, prisma };
}

/** The app's own pipe options, so a refused body is refused exactly as deployed. */
const pipe = new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true });

async function changePrice(body: unknown, controller: BillingController): Promise<unknown> {
  const dto = (await pipe.transform(body, { type: 'body', metatype: PriceDto })) as PriceDto;

  return controller.changePrice(dto, request);
}

/** Out of bounds, non-positive, three decimals, a currency, an unknown key. */
const REFUSED_BODIES: Record<string, unknown>[] = [
  { priceUsd: '10000' },
  { priceUsd: '0.00' },
  { priceUsd: '4.200' },
  { priceUsd: '4.20EUR' },
  { priceUsd: '4.20', currency: 'EUR' },
];

describe('BillingController price route', () => {
  it('is staff-only: ADMIN and OWNER, never USER or ATHLETE', () => {
    expect(Reflect.getMetadata(ROLES_KEY, BillingController.prototype.changePrice)).toEqual([
      Role.ADMIN,
      Role.OWNER,
    ]);
  });

  it('requires a step-up proof even with a staff role', () => {
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, BillingController.prototype.changePrice)).toBe(
      true,
    );
  });

  it('hands the principal, the new amount and the request id to the service', async () => {
    const { controller, audit, prisma } = build();

    await expect(changePrice({ priceUsd: '4.50' }, controller)).resolves.toEqual({
      code: 'standard',
      priceUsd: '4.50',
      periodKey: 'default',
      periodDays: 365,
    });
    expect(prisma.transactions).toBe(1);
    expect(audit.records).toHaveLength(1);
  });

  it.each(REFUSED_BODIES)('refuses %j before the service is reached', async (body) => {
    const { controller, audit, prisma } = build();

    await expect(changePrice(body, controller)).rejects.toBeInstanceOf(BadRequestException);

    expect(prisma.transactions).toBe(0);
    expect(audit.records).toHaveLength(0);
  });
});
