import type { PaymentProvider } from '@prisma/client';
import type { CheckoutRequest, CheckoutSession, PaymentSessionClient } from '../payment-session';
import type { PayPalApi } from './paypal.api';

interface OrderReply {
  readonly id?: unknown;
  readonly links?: readonly { readonly rel?: unknown; readonly href?: unknown }[];
}

/**
 * Opens a PayPal order and returns the approval page.
 *
 * The order is created server-side with the amount and currency this server
 * decided; the client never sends a price, and the athlete only ever sees the
 * hosted PayPal page.
 */
export class PayPalSessionClient implements PaymentSessionClient {
  readonly provider: PaymentProvider = 'PAYPAL';

  constructor(private readonly api: PayPalApi) {}

  async createCheckout(request: CheckoutRequest): Promise<CheckoutSession> {
    const order = await this.api.json<OrderReply>('/v2/checkout/orders', {
      method: 'POST',
      body: {
        intent: 'CAPTURE',
        purchase_units: [
          {
            reference_id: request.reference,
            description: 'KFA athlete subscription',
            amount: { currency_code: request.currency, value: request.amount },
          },
        ],
        application_context: {
          return_url: request.returnUrl,
          cancel_url: request.returnUrl,
          user_action: 'PAY_NOW',
        },
      },
    });

    const approve = order.links?.find((link) => link.rel === 'approve')?.href;

    if (typeof order.id !== 'string' || typeof approve !== 'string') {
      throw new Error('paypal order malformed');
    }

    return { providerPaymentId: order.id, redirectUrl: approve };
  }
}
