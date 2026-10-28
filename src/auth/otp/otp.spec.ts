import { FakeOtpProvider } from './otp.provider';

describe('FakeOtpProvider', () => {
  it('accepts only the fixed development code', async () => {
    const provider = new FakeOtpProvider();
    await expect(provider.start('+14155552671', {})).resolves.toEqual({ challengeRef: null });
    await expect(provider.check('+14155552671', '123456', null)).resolves.toBe(true);
    await expect(provider.check('+14155552671', '000000', null)).resolves.toBe(false);
  });
});
