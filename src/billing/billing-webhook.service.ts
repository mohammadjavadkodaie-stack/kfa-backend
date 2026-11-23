import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { PaymentProvider } from '@prisma/client';
import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { WEBHOOK_VERIFIERS } from './billing.tokens';
import type { NormalizedEvent, WebhookHeaders, WebhookVerifier } from './webhook-verifier';

export type WebhookVerifiers =
  ReadonlyMap<string, WebhookVerifier> | Readonly<Record<string, WebhookVerifier>>;

/**
 * What the caller may tell the provider.
 *
 * `accepted` is true once the delivery is stored, even when it changed nothing
 * (a replay, an unknown payment, a guarded transition). `knownProvider` is false
 * when no verifier is configured, so nothing was read and the route can answer
 * as if it did not exist.
 */
export type WebhookOutcome = {
  readonly accepted: boolean;
  readonly knownProvider: boolean;
  /** True when the delivery must be retried by the provider (a generic 503). */
  readonly retryLater: boolean;
};

function verifierFor(verifiers: WebhookVerifiers, provider: string): WebhookVerifier | undefined {
  if (verifiers instanceof Map) return verifiers.get(provider);
  return (verifiers as Readonly<Record<string, WebhookVerifier>>)[provider];
}

@Injectable()
export class BillingWebhookService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(WEBHOOK_VERIFIERS)
    private readonly verifiers: WebhookVerifiers,
  ) {}

  async handle(
    provider: string,
    rawBody: Buffer,
    headers: WebhookHeaders,
  ): Promise<WebhookOutcome> {
    const verifier = verifierFor(this.verifiers, provider);
    if (verifier === undefined) {
      return { accepted: false, knownProvider: false, retryLater: false };
    }

    const verification = await verifier.verify(rawBody, headers);

    // The verifier could not decide: nothing is stored, and the provider is told
    // to send the delivery again instead of being handed a 2xx for a payment it
    // may well have taken.
    if (verification.status === 'unavailable') {
      return { accepted: false, knownProvider: true, retryLater: true };
    }

    if (verification.status === 'invalid') {
      await this.audit.record({ action: 'billing.webhook.rejected', metadata: { provider } });
      return { accepted: false, knownProvider: true, retryLater: false };
    }

    const event = verification.event;
    const payloadHash = createHash('sha256').update(rawBody).digest('hex');
    await this.prisma.$transaction(async (tx) => {
      const inserted = await tx.webhookEvent.createMany({
        data: {
          provider: provider as PaymentProvider,
          eventId: event.eventId,
          payloadHash,
          signatureValid: true,
        },
        skipDuplicates: true,
      });
      if (inserted.count === 0) return;

      const payment = await tx.payment.findUnique({
        where: {
          provider_providerPaymentId: {
            provider: provider as PaymentProvider,
            providerPaymentId: event.providerPaymentId,
          },
        },
        select: {
          id: true,
          subscriptionId: true,
          status: true,
          expectedAmount: true,
          expectedCurrency: true,
          expectedNetwork: true,
        },
      });
      let outcome: string;
      if (payment === null) {
        outcome = 'unknown_payment';
        await this.audit.record(
          { action: 'billing.webhook.unknown_payment', metadata: { provider, outcome } },
          tx,
        );
      } else {
        outcome = await this.applyEvent(tx, provider, event, payment);
      }
      await tx.webhookEvent.update({
        where: {
          provider_eventId: { provider: provider as PaymentProvider, eventId: event.eventId },
        },
        data: { processedAt: new Date(), outcome },
      });
    });
    return { accepted: true, knownProvider: true, retryLater: false };
  }

  private async applyEvent(
    tx: Prisma.TransactionClient,
    provider: string,
    event: NormalizedEvent,
    payment: {
      id: string;
      subscriptionId: string;
      status: string;
      expectedAmount: Prisma.Decimal;
      expectedCurrency: string;
      expectedNetwork: string | null;
    },
  ): Promise<string> {
    // A verified event this service does not model: store it so the provider
    // stops resending, and change nothing else.
    if (event.kind === 'IGNORED') {
      await tx.webhookEvent.update({
        where: {
          provider_eventId: {
            provider: provider as PaymentProvider,
            eventId: event.eventId,
          },
        },
        data: { processedAt: new Date(), outcome: 'ignored_event' },
      });
      return 'ignored_event';
    }

    if (event.kind === 'PAID') {
      const paidAmount =
        event.paidAmount === undefined ? null : new Prisma.Decimal(event.paidAmount);
      const mismatch =
        paidAmount === null ||
        paidAmount.lt(payment.expectedAmount) ||
        event.currency !== payment.expectedCurrency ||
        (event.network ?? null) !== (payment.expectedNetwork ?? null);
      if (mismatch) {
        await tx.payment.updateMany({
          where: { id: payment.id, status: { in: ['CREATED', 'PENDING'] } },
          data: { status: 'FAILED' },
        });
        await this.audit.record(
          {
            action: 'billing.webhook.amount_mismatch',
            metadata: { provider, outcome: 'amount_mismatch' },
          },
          tx,
        );
        return 'amount_mismatch';
      }
      const paymentUpdate = await tx.payment.updateMany({
        where: { id: payment.id, status: { in: ['CREATED', 'PENDING'] } },
        data: { status: 'CONFIRMED', paidAmount, confirmedAt: new Date() },
      });
      if (paymentUpdate.count === 0) return this.ignored(tx, provider);
      await tx.subscription.updateMany({
        where: { id: payment.subscriptionId, status: { in: ['NONE', 'PENDING'] } },
        data: { status: 'ACTIVE', startsAt: new Date() },
      });
      await this.audit.record(
        { action: 'billing.webhook.applied', metadata: { provider, outcome: 'applied' } },
        tx,
      );
      return 'applied';
    }
    if (event.kind === 'PENDING') {
      const result = await tx.payment.updateMany({
        where: { id: payment.id, status: 'CREATED' },
        data: { status: 'PENDING' },
      });
      if (result.count === 0) return this.ignored(tx, provider);
      await tx.subscription.updateMany({
        where: { id: payment.subscriptionId, status: 'NONE' },
        data: { status: 'PENDING' },
      });
      await this.audit.record(
        { action: 'billing.webhook.applied', metadata: { provider, outcome: 'applied' } },
        tx,
      );
      return 'applied';
    }
    if (event.kind === 'FAILED') {
      const result = await tx.payment.updateMany({
        where: { id: payment.id, status: { in: ['CREATED', 'PENDING'] } },
        data: { status: 'FAILED' },
      });
      if (result.count === 0) return this.ignored(tx, provider);
      await this.audit.record(
        { action: 'billing.webhook.applied', metadata: { provider, outcome: 'applied' } },
        tx,
      );
      return 'applied';
    }
    const status = event.kind === 'REFUNDED' ? 'REFUNDED' : 'CHARGEBACK';
    const result = await tx.payment.updateMany({
      where: { id: payment.id, status: 'CONFIRMED' },
      data: { status },
    });
    if (result.count === 0) return this.ignored(tx, provider);
    await tx.subscription.updateMany({
      where: { id: payment.subscriptionId, status: 'ACTIVE' },
      data: { status: 'REFUNDED' },
    });
    await this.audit.record(
      { action: 'billing.webhook.applied', metadata: { provider, outcome: 'applied' } },
      tx,
    );
    return 'applied';
  }

  private async ignored(tx: Prisma.TransactionClient, provider: string): Promise<string> {
    await this.audit.record(
      {
        action: 'billing.webhook.ignored_transition',
        metadata: { provider, outcome: 'ignored_transition' },
      },
      tx,
    );
    return 'ignored_transition';
  }
}
