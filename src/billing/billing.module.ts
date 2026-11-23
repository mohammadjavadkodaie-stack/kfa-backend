import { Module } from '@nestjs/common';
import type { PaymentProvider } from '@prisma/client';
import { AuditModule } from '../audit/audit.module';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { BillingCheckoutService } from './billing-checkout.service';
import { BillingController } from './billing.controller';
import { BillingWebhookController } from './billing-webhook.controller';
import { BillingWebhookService } from './billing-webhook.service';
import {
  BILLING_PLAN_REPOSITORY,
  BILLING_STORE,
  PAYMENT_SESSION_CLIENTS,
  WEBHOOK_VERIFIERS,
  type PaymentSessionClients,
  type WebhookVerifiers,
} from './billing.tokens';
import type { PaymentSessionClient } from './payment-session';
import { PrismaBillingPlanRepository } from './prisma-billing-plan.repository';
import { PrismaBillingStore } from './prisma-billing.store';
import { NowPaymentsSessionClient } from './providers/nowpayments.client';
import { NowPaymentsVerifier } from './providers/nowpayments.verifier';
import { PayPalApi } from './providers/paypal.api';
import { PayPalSessionClient } from './providers/paypal.client';
import { PayPalWebhookVerifier } from './providers/paypal.verifier';
import type { WebhookVerifier } from './webhook-verifier';

/**
 * Both provider maps come from one validated environment. A provider is either
 * fully configured or absent (the boot check refuses half of it), and an absent
 * provider can be neither sold nor trusted - the safe state for a deployment
 * that has not been given live credentials yet.
 */
export interface BillingProviders {
  readonly sessions: PaymentSessionClients;
  readonly verifiers: WebhookVerifiers;
}

export function buildBillingProviders(env: Env): BillingProviders {
  const sessions = new Map<PaymentProvider, PaymentSessionClient>();
  const verifiers = new Map<string, WebhookVerifier>();
  const webhookBase = env.BILLING_WEBHOOK_PUBLIC_URL?.replace(/\/+$/u, '');

  if (env.NOWPAYMENTS_API_KEY !== undefined && webhookBase !== undefined) {
    sessions.set(
      'NOWPAYMENTS',
      new NowPaymentsSessionClient(
        env.NOWPAYMENTS_API_KEY,
        env.NOWPAYMENTS_API_BASE,
        `${webhookBase}/nowpayments`,
      ),
    );
  }

  if (env.NOWPAYMENTS_IPN_SECRET !== undefined) {
    verifiers.set('NOWPAYMENTS', new NowPaymentsVerifier(env.NOWPAYMENTS_IPN_SECRET));
  }

  // One PayPal client for both jobs: the OAuth token is cached inside it.
  const paypal =
    env.PAYPAL_CLIENT_ID !== undefined && env.PAYPAL_CLIENT_SECRET !== undefined
      ? new PayPalApi(env.PAYPAL_CLIENT_ID, env.PAYPAL_CLIENT_SECRET, env.PAYPAL_API_BASE)
      : null;

  if (paypal !== null) {
    sessions.set('PAYPAL', new PayPalSessionClient(paypal));

    if (env.PAYPAL_WEBHOOK_ID !== undefined) {
      verifiers.set('PAYPAL', new PayPalWebhookVerifier(paypal, env.PAYPAL_WEBHOOK_ID));
    }
  }

  return { sessions, verifiers };
}

/** The pair of maps, built once per process. */
const BILLING_PROVIDERS = Symbol('BILLING_PROVIDERS');

@Module({
  imports: [AuditModule, RateLimitModule],
  controllers: [BillingWebhookController, BillingController],
  providers: [
    BillingWebhookService,
    BillingCheckoutService,
    { provide: BILLING_PLAN_REPOSITORY, useClass: PrismaBillingPlanRepository },
    { provide: BILLING_STORE, useClass: PrismaBillingStore },
    {
      provide: BILLING_PROVIDERS,
      inject: [ENV],
      useFactory: (env: Env): BillingProviders => buildBillingProviders(env),
    },
    {
      provide: WEBHOOK_VERIFIERS,
      inject: [BILLING_PROVIDERS],
      useFactory: (providers: BillingProviders): WebhookVerifiers => providers.verifiers,
    },
    {
      provide: PAYMENT_SESSION_CLIENTS,
      inject: [BILLING_PROVIDERS],
      useFactory: (providers: BillingProviders): PaymentSessionClients => providers.sessions,
    },
  ],
})
export class BillingModule {}
