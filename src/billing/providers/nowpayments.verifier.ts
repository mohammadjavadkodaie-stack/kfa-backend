import { createHmac, timingSafeEqual } from 'node:crypto';
import type { NormalizedEvent, WebhookHeaders, WebhookVerifier } from '../webhook-verifier';
import { readWebhookHeader } from '../webhook-verifier';

const SIGNATURE_HEADER = 'x-nowpayments-sig';

/** NOWPayments status -> our kind. A status we do not model is stored, ignored. */
const KINDS: Readonly<Record<string, NormalizedEvent['kind']>> = {
  waiting: 'PENDING',
  confirming: 'PENDING',
  sending: 'PENDING',
  finished: 'PAID',
  failed: 'FAILED',
  expired: 'FAILED',
  // An underpayment is never a completed payment: same refusal as a wrong amount.
  partially_paid: 'FAILED',
  refunded: 'REFUNDED',
};

/**
 * The HMAC-SHA512 signature NOWPayments sends, over the body with its keys
 * sorted. Sorted because JSON key order is not stable, and the signature must
 * not depend on it.
 */
export function nowPaymentsSignature(rawBody: Buffer, ipnSecret: string): string | null {
  let payload: unknown;

  try {
    payload = JSON.parse(rawBody.toString('utf8')) as unknown;
  } catch {
    return null;
  }

  return createHmac('sha512', ipnSecret)
    .update(JSON.stringify(sortKeys(payload)))
    .digest('hex');
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);

  if (value === null || typeof value !== 'object') return value;

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, entry]) => [key, sortKeys(entry)]),
  );
}

export class NowPaymentsVerifier implements WebhookVerifier {
  readonly provider = 'NOWPAYMENTS';

  constructor(private readonly ipnSecret: string) {}

  async verify(rawBody: Buffer, headers: WebhookHeaders): Promise<NormalizedEvent | null> {
    const signature = readWebhookHeader(headers, SIGNATURE_HEADER);
    const expected = nowPaymentsSignature(rawBody, this.ipnSecret);

    if (signature === null || expected === null) return null;
    if (!sameHex(signature, expected)) return null;

    return normalize(rawBody);
  }
}

function sameHex(given: string, expected: string): boolean {
  const left = Buffer.from(given, 'utf8');
  const right = Buffer.from(expected, 'utf8');

  return left.length === right.length && timingSafeEqual(left, right);
}

function normalize(rawBody: Buffer): NormalizedEvent | null {
  let payload: Record<string, unknown>;

  try {
    payload = JSON.parse(rawBody.toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }

  const status = typeof payload.payment_status === 'string' ? payload.payment_status : null;
  const invoiceId = identifier(payload.invoice_id);

  if (status === null || invoiceId === null) return null;

  const kind = KINDS[status] ?? 'IGNORED';
  const payCurrency = (
    typeof payload.pay_currency === 'string' ? payload.pay_currency : ''
  ).toLowerCase();
  const paid = typeof payload.actually_paid === 'string' ? payload.actually_paid : undefined;

  return {
    // A status is one event: the same invoice reporting "finished" twice is one
    // row, and a later "refunded" is a different one.
    eventId: `${invoiceId}:${status}`,
    providerPaymentId: invoiceId,
    kind,
    paidAmount: kind === 'PAID' ? paid : undefined,
    currency:
      kind === 'PAID'
        ? payCurrency.startsWith('usdt')
          ? 'USDT'
          : payCurrency.toUpperCase()
        : undefined,
    network: kind === 'PAID' ? (payCurrency === 'usdttrc20' ? 'TRC20' : null) : undefined,
  };
}

/** NOWPayments sends ids as strings today; a number would otherwise slip through. */
function identifier(value: unknown): string | null {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return String(value);

  return null;
}
