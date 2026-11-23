import type { BillingPlanRepository } from './billing-plan';
import type { BillingStore } from './billing.store';
import type { WebhookVerifiers } from './billing-webhook.service';
import type { PaymentSessionClients } from './payment-session';

/**
 * DI token for the provider verifiers.
 *
 * It lives in its own file so the service, the module and the specs can share it
 * without importing each other in a cycle. Type-only imports keep this module
 * free of runtime dependencies.
 */
export const WEBHOOK_VERIFIERS = Symbol('WEBHOOK_VERIFIERS');

/** The priced offer the checkout reads and the price endpoint writes. */
export const BILLING_PLAN_REPOSITORY = Symbol('BILLING_PLAN_REPOSITORY');

/** Subscription and payment rows, behind a seam the specs can replace. */
export const BILLING_STORE = Symbol('BILLING_STORE');

/** Hosted checkout clients, one per configured provider. */
export const PAYMENT_SESSION_CLIENTS = Symbol('PAYMENT_SESSION_CLIENTS');

/** Re-exported here so a provider can be typed without a second import. */
export type { WebhookVerifiers };
export type { BillingPlanRepository };
export type { BillingStore };
export type { PaymentSessionClients };
