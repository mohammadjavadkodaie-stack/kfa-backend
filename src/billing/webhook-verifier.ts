export type WebhookHeaders = Record<string, string | string[] | undefined>;

export interface NormalizedEvent {
  readonly eventId: string;
  readonly providerPaymentId: string;
  readonly kind: 'PENDING' | 'PAID' | 'FAILED' | 'REFUNDED' | 'CHARGEBACK';
  readonly paidAmount?: string;
  readonly currency?: string;
  readonly network?: string | null;
}

export interface WebhookVerifier {
  readonly provider: string;
  verify(rawBody: Buffer, headers: WebhookHeaders): NormalizedEvent | null;
}
