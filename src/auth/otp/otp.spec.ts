import { createOtpProvider, FakeOtpProvider } from './otp.provider';

describe('FakeOtpProvider', () => {
  it('accepts only the fixed development code', async () => {
    const provider = new FakeOtpProvider();
    await expect(provider.start('+14155552671', { purpose: 'login' })).resolves.toEqual({
      challengeRef: null,
    });
    await expect(provider.check('+14155552671', '123456', null)).resolves.toBe(true);
    await expect(provider.check('+14155552671', '000000', null)).resolves.toBe(false);
  });
});

describe('createOtpProvider', () => {
  it.each(['development', 'test'] as const)('serves the fake provider in %s', (nodeEnv) => {
    expect(createOtpProvider({ NODE_ENV: nodeEnv, OTP_PROVIDER: 'fake' })).toBeInstanceOf(
      FakeOtpProvider,
    );
  });

  it.each(['fake', 'twilio'] as const)(
    'fails closed in production whatever OTP_PROVIDER says (%s)',
    async (otpProvider) => {
      const provider = createOtpProvider({ NODE_ENV: 'production', OTP_PROVIDER: otpProvider });

      expect(provider).not.toBeInstanceOf(FakeOtpProvider);

      await expect(provider.start('+14155552671', { purpose: 'login' })).rejects.toThrow(
        /OTP flow is disabled in production/,
      );
      await expect(provider.check('+14155552671', '123456', null)).rejects.toThrow(
        /OTP flow is disabled in production/,
      );
      await expect(
        provider.notify('+14155552671', { kind: 'phone_changed', maskedPhone: '***-***-2671' }),
      ).rejects.toThrow(/OTP flow is disabled in production/);
    },
  );

  it('refuses a provider that has no adapter', () => {
    expect(() => createOtpProvider({ NODE_ENV: 'test', OTP_PROVIDER: 'twilio' })).toThrow(
      /Unsupported OTP_PROVIDER/,
    );
  });
});
