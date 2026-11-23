import type { PaymentProvider } from '@prisma/client';

/** What a provider needs to open a hosted checkout page. */
export interface CheckoutRequest {
  /** Opaque reference we choose, so a delivery can be traced back to this call. */
  readonly reference: string;
  /** Decimal string, already the price of the offer. */
  readonly amount: string;
  /** What the provider charges in: `USD` for PayPal, `USDT` for NOWPayments. */
  readonly currency: string;
  /** Where the athlete lands after paying or cancelling. */
  readonly returnUrl: string;
}

export interface CheckoutSession {
  /** The id the provider's webhook will report for this payment. */
  readonly providerPaymentId: string;
  /** The hosted page the browser is sent to. */
  readonly redirectUrl: string;
}

/** The only thing the checkout asks a provider to do. */
export interface PaymentSessionClient {
  readonly provider: PaymentProvider;
  createCheckout(request: CheckoutRequest): Promise<CheckoutSession>;
}

export type PaymentSessionClients = ReadonlyMap<PaymentProvider, PaymentSessionClient>;
