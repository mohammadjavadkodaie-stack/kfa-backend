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

  it('refuses to start in production when the fake provider is selected', () => {
    expect(() => createOtpProvider({ NODE_ENV: 'production', OTP_PROVIDER: 'fake' })).toThrow(
      /OTP_PROVIDER=fake is not allowed in NODE_ENV=production/,
    );
  });

  it('refuses a provider that has no adapter', () => {
    expect(() => createOtpProvider({ NODE_ENV: 'test', OTP_PROVIDER: 'twilio' })).toThrow(
      /Unsupported OTP_PROVIDER/,
    );
  });
});
