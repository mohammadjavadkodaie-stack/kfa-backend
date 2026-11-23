import type { PaymentProvider } from '@prisma/client';
import type { CheckoutRequest, CheckoutSession, PaymentSessionClient } from '../payment-session';

const TIMEOUT_MS = 10_000;

type FetchLike = typeof fetch;

interface InvoiceReply {
  readonly id?: unknown;
  readonly invoice_url?: unknown;
}

/**
 * Opens a NOWPayments invoice for the USDT TRC20 amount.
 *
 * The amount and the currency are chosen here, from the stored offer; the price
 * the athlete sees is whatever the hosted invoice shows, and the webhook is
 * matched against the invoice id returned by this call.
 */
export class NowPaymentsSessionClient implements PaymentSessionClient {
  readonly provider: PaymentProvider = 'NOWPAYMENTS';

  constructor(
    private readonly apiKey: string,
    private readonly baseUrl: string,
    private readonly ipnUrl: string,
    private readonly fetchFn: FetchLike = fetch,
  ) {}

  async createCheckout(request: CheckoutRequest): Promise<CheckoutSession> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await this.fetchFn(`${this.baseUrl}/v1/invoice`, {
        method: 'POST',
        headers: { 'x-api-key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          price_amount: Number(request.amount),
          price_currency: 'usd',
          pay_currency: 'usdttrc20',
          order_id: request.reference,
          order_description: 'KFA athlete subscription',
          ipn_callback_url: this.ipnUrl,
          success_url: request.returnUrl,
          cancel_url: request.returnUrl,
        }),
        signal: controller.signal,
      });

      if (!response.ok) throw new Error(`nowpayments invoice failed (${response.status})`);

      const reply = (await response.json()) as InvoiceReply;

      if (typeof reply.id !== 'string' || typeof reply.invoice_url !== 'string') {
        throw new Error('nowpayments invoice malformed');
      }

      return { providerPaymentId: reply.id, redirectUrl: reply.invoice_url };
    } finally {
      clearTimeout(timeout);
    }
  }
}
