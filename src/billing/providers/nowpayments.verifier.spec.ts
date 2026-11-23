import { NowPaymentsVerifier, nowPaymentsSignature, readPaidAmount } from './nowpayments.verifier';

const SECRET = 'ipn-secret-value-123456';
const BODY = {
  payment_status: 'finished',
  invoice_id: 'inv-1',
  payment_id: 'pay-1',
  pay_currency: 'usdttrc20',
  actually_paid: '4.2',
};

function signed(payload: Record<string, unknown>): {
  readonly raw: Buffer;
  readonly headers: Record<string, string>;
} {
  const raw = Buffer.from(JSON.stringify(payload), 'utf8');

  return { raw, headers: { 'x-nowpayments-sig': nowPaymentsSignature(raw, SECRET) ?? '' } };
}

describe('NowPaymentsVerifier', () => {
  const verifier = new NowPaymentsVerifier(SECRET);

  it('reads a signed payment as the invoice it belongs to', async () => {
    const { raw, headers } = signed(BODY);

    await expect(verifier.verify(raw, headers)).resolves.toEqual({
      status: 'event',
      event: {
        eventId: 'inv-1:finished',
        providerPaymentId: 'inv-1',
        kind: 'PAID',
        paidAmount: '4.2',
        currency: 'USDT',
        network: 'TRC20',
      },
    });
  });

  it('accepts the paid amount as a number too', async () => {
    const { raw, headers } = signed({ ...BODY, actually_paid: 4.2 });

    const result = await verifier.verify(raw, headers);

    expect(result).toMatchObject({ status: 'event', event: { kind: 'PAID' } });
    expect(result.status === 'event' ? result.event.paidAmount : null).toBe('4.200000');
  });

  it('drops a paid amount it cannot read', async () => {
    const { raw, headers } = signed({ ...BODY, actually_paid: 'NaN' });

    const result = await verifier.verify(raw, headers);

    expect(result.status).toBe('event');
    expect(result.status === 'event' ? result.event.paidAmount : 'x').toBeUndefined();
  });

  it('treats an underpayment as pending, so the rest can still arrive', async () => {
    const { raw, headers } = signed({ ...BODY, payment_status: 'partially_paid' });

    await expect(verifier.verify(raw, headers)).resolves.toMatchObject({
      status: 'event',
      event: { kind: 'PENDING' },
    });
  });

  it('does not depend on the order of the keys', async () => {
    const { raw } = signed(BODY);
    const reordered = Buffer.from(
      JSON.stringify({
        actually_paid: '4.2',
        pay_currency: 'usdttrc20',
        payment_id: 'pay-1',
        invoice_id: 'inv-1',
        payment_status: 'finished',
      }),
      'utf8',
    );
    const signature = nowPaymentsSignature(raw, SECRET) ?? '';

    await expect(
      verifier.verify(reordered, { 'x-nowpayments-sig': signature }),
    ).resolves.toMatchObject({ status: 'event', event: { kind: 'PAID' } });
  });

  it('refuses a body that was changed after signing', async () => {
    const { headers } = signed(BODY);
    const tampered = Buffer.from(JSON.stringify({ ...BODY, actually_paid: '0.1' }), 'utf8');

    await expect(verifier.verify(tampered, headers)).resolves.toEqual({ status: 'invalid' });
  });

  it('refuses a body with no signature at all', async () => {
    const { raw } = signed(BODY);

    await expect(verifier.verify(raw, {})).resolves.toEqual({ status: 'invalid' });
  });

  it('records a status it does not model without acting on it', async () => {
    const { raw, headers } = signed({ ...BODY, payment_status: 'something_new' });

    await expect(verifier.verify(raw, headers)).resolves.toMatchObject({
      status: 'event',
      event: { kind: 'IGNORED' },
    });
  });

  it('refuses a body that is not JSON', async () => {
    const raw = Buffer.from('not json', 'utf8');

    await expect(verifier.verify(raw, { 'x-nowpayments-sig': 'abcd' })).resolves.toEqual({
      status: 'invalid',
    });
  });
});

describe('readPaidAmount', () => {
  it('keeps a decimal string as it is', () => {
    expect(readPaidAmount('4.2')).toBe('4.2');
    expect(readPaidAmount('0')).toBe('0');
  });

  it('writes a number as a fixed decimal', () => {
    expect(readPaidAmount(4.2)).toBe('4.200000');
  });

  it('refuses what is not an amount', () => {
    expect(readPaidAmount('')).toBeUndefined();
    expect(readPaidAmount('abc')).toBeUndefined();
    expect(readPaidAmount(-1)).toBeUndefined();
    expect(readPaidAmount(Number.NaN)).toBeUndefined();
    expect(readPaidAmount(Number.POSITIVE_INFINITY)).toBeUndefined();
    expect(readPaidAmount(1e12)).toBeUndefined();
    expect(readPaidAmount(null)).toBeUndefined();
  });
});
