import type { NormalizedEvent, WebhookHeaders, WebhookVerifier } from '../webhook-verifier';
import { readWebhookHeader } from '../webhook-verifier';
import type { PayPalApi } from './paypal.api';

/** The five headers PayPal signs with; a missing one is a refused delivery. */
const SIGNATURE_HEADERS = [
  'paypal-transmission-id',
  'paypal-transmission-time',
  'paypal-cert-url',
  'paypal-auth-algo',
  'paypal-transmission-sig',
] as const;

/** Event type -> state. A verified type outside this table is stored and ignored. */
const KINDS: Readonly<Record<string, NormalizedEvent['kind']>> = {
  'PAYMENT.CAPTURE.COMPLETED': 'PAID',
  'PAYMENT.CAPTURE.PENDING': 'PENDING',
  'PAYMENT.CAPTURE.DENIED': 'FAILED',
  'PAYMENT.CAPTURE.DECLINED': 'FAILED',
  'PAYMENT.CAPTURE.REFUNDED': 'REFUNDED',
  'PAYMENT.CAPTURE.REVERSED': 'CHARGEBACK',
};

interface VerificationReply {
  readonly verification_status?: unknown;
}

/**
 * PayPal does not hand out a local signing secret: the signature is confirmed by
 * their own API, with the headers and the event body. Anything other than
 * `SUCCESS` - including a timeout - refuses the delivery, so a network failure
 * can never be mistaken for a valid payment.
 */
export class PayPalWebhookVerifier implements WebhookVerifier {
  readonly provider = 'PAYPAL';

  constructor(
    private readonly api: PayPalApi,
    private readonly webhookId: string,
  ) {}

  async verify(rawBody: Buffer, headers: WebhookHeaders): Promise<NormalizedEvent | null> {
    const values = SIGNATURE_HEADERS.map((name) => readWebhookHeader(headers, name));

    if (values.some((value) => value === null)) return null;

    const [transmissionId, transmissionTime, certUrl, authAlgo, transmissionSig] = values as [
      string,
      string,
      string,
      string,
      string,
    ];

    let event: Record<string, unknown>;

    try {
      event = JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }

    let reply: VerificationReply;

    try {
      reply = await this.api.json<VerificationReply>('/v1/notifications/verify-webhook-signature', {
        method: 'POST',
        body: {
          transmission_id: transmissionId,
          transmission_time: transmissionTime,
          cert_url: certUrl,
          auth_algo: authAlgo,
          transmission_sig: transmissionSig,
          webhook_id: this.webhookId,
          webhook_event: event,
        },
      });
    } catch {
      return null;
    }

    return reply.verification_status === 'SUCCESS' ? normalize(event) : null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The order id, which is what the checkout stored. A capture or refund id is a
 * different identifier and would never match a payment row.
 */
function relatedOrderId(resource: Record<string, unknown>): string | null {
  const supplementary = isRecord(resource.supplementary_data) ? resource.supplementary_data : null;
  const related =
    supplementary !== null && isRecord(supplementary.related_ids)
      ? supplementary.related_ids
      : null;
  const orderId = related === null ? null : related.order_id;

  return typeof orderId === 'string' && orderId.length > 0 ? orderId : null;
}

function normalize(event: Record<string, unknown>): NormalizedEvent | null {
  const eventId = typeof event.id === 'string' && event.id.length > 0 ? event.id : null;
  const type = typeof event.event_type === 'string' ? event.event_type : null;
  const resource = isRecord(event.resource) ? event.resource : null;

  if (eventId === null || type === null || resource === null) return null;

  const providerPaymentId = relatedOrderId(resource);

  // Without an order id there is no row this event could ever belong to.
  if (providerPaymentId === null) return null;

  const kind = KINDS[type] ?? 'IGNORED';
  const amount = isRecord(resource.amount) ? resource.amount : null;
  const paidAmount =
    kind === 'PAID' && amount !== null && typeof amount.value === 'string'
      ? amount.value
      : undefined;
  const currency =
    kind === 'PAID' && amount !== null && typeof amount.currency_code === 'string'
      ? amount.currency_code
      : undefined;

  return {
    eventId,
    providerPaymentId,
    kind,
    paidAmount,
    currency,
    network: kind === 'PAID' ? null : undefined,
  };
}
