export type WebhookHeaders = Record<string, string | string[] | undefined>;

export interface NormalizedEvent {
  readonly eventId: string;
  readonly providerPaymentId: string;
  /**
   * `IGNORED` is a verified event we do not model: it is stored so the provider
   * stops resending it, and it changes nothing else.
   */
  readonly kind: 'PENDING' | 'PAID' | 'FAILED' | 'REFUNDED' | 'CHARGEBACK' | 'IGNORED';
  readonly paidAmount?: string;
  readonly currency?: string;
  readonly network?: string | null;
}

export interface WebhookVerifier {
  readonly provider: string;
  /**
   * Async because PayPal's own answer decides the signature: the bytes are
   * checked by their API, not by a local secret.
   */
  verify(rawBody: Buffer, headers: WebhookHeaders): Promise<NormalizedEvent | null>;
}

/** First value of a header, or null. A repeated header is not trusted. */
export function readWebhookHeader(headers: WebhookHeaders, name: string): string | null {
  const value = headers[name];

  if (typeof value === 'string') return value.length === 0 ? null : value;

  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === 'string' && first.length > 0 ? first : null;
  }

  return null;
}
