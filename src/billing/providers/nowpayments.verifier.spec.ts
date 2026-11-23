import { NowPaymentsVerifier, nowPaymentsSignature } from './nowpayments.verifier';

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
      eventId: 'inv-1:finished',
      providerPaymentId: 'inv-1',
      kind: 'PAID',
      paidAmount: '4.2',
      currency: 'USDT',
      network: 'TRC20',
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
    ).resolves.toMatchObject({ kind: 'PAID' });
  });

  it('refuses a body that was changed after signing', async () => {
    const { headers } = signed(BODY);
    const tampered = Buffer.from(JSON.stringify({ ...BODY, actually_paid: '0.1' }), 'utf8');

    await expect(verifier.verify(tampered, headers)).resolves.toBeNull();
  });

  it('refuses a body with no signature at all', async () => {
    const { raw } = signed(BODY);

    await expect(verifier.verify(raw, {})).resolves.toBeNull();
  });

  it('records a status it does not model without acting on it', async () => {
    const { raw, headers } = signed({ ...BODY, payment_status: 'something_new' });

    await expect(verifier.verify(raw, headers)).resolves.toMatchObject({ kind: 'IGNORED' });
  });

  it('treats an underpayment as a failed payment', async () => {
    const { raw, headers } = signed({ ...BODY, payment_status: 'partially_paid' });

    await expect(verifier.verify(raw, headers)).resolves.toMatchObject({ kind: 'FAILED' });
  });

  it('refuses a body that is not JSON', async () => {
    const raw = Buffer.from('not json', 'utf8');

    await expect(verifier.verify(raw, { 'x-nowpayments-sig': 'abcd' })).resolves.toBeNull();
  });
});
