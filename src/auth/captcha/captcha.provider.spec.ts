import { loadEnv } from '../../config/env';
import { createCaptchaProvider, FakeCaptchaProvider } from './captcha.provider';

/** Minimal valid environment for the config schema; the captcha key is absent. */
const DEV_ENV_WITHOUT_CAPTCHA: NodeJS.ProcessEnv = {
  NODE_ENV: 'development',
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:dev-secret@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
  OTP_PROOF_SECRET: 'unit-test-otp-proof-secret-0123456789abcdef',
  ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
  DOCUMENT_VIEW_TOKEN_SECRET: 'unit-test-view-token-secret-0123456789abcdef',
  EMAIL_CODE_HMAC_KEY: 'unit-test-email-code-hmac-key-0123456789',
};

describe('FakeCaptchaProvider', () => {
  it('accepts the legacy test token by default and rejects a wrong one', async () => {
    const provider = new FakeCaptchaProvider();
    await expect(provider.verify('fake-captcha-pass')).resolves.toBe(true);
    await expect(provider.verify('wrong-token')).resolves.toBe(false);
  });

  it('accepts the frontend dev token outside production', async () => {
    const provider = new FakeCaptchaProvider('development');
    await expect(provider.verify('fake-captcha-token')).resolves.toBe(true);
    await expect(new FakeCaptchaProvider('test').verify('fake-captcha-token')).resolves.toBe(true);
  });

  it('never accepts the frontend dev token in production', async () => {
    const provider = new FakeCaptchaProvider('production');
    await expect(provider.verify('fake-captcha-token')).resolves.toBe(false);
  });

  it('rejects any other token outside production', async () => {
    const provider = new FakeCaptchaProvider('development');
    await expect(provider.verify('fake-captcha-token-wrong')).resolves.toBe(false);
    await expect(provider.verify('')).resolves.toBe(false);
  });
});

describe('createCaptchaProvider', () => {
  it('resolves an unset CAPTCHA_PROVIDER in development to the fake verifier', async () => {
    const env = loadEnv(DEV_ENV_WITHOUT_CAPTCHA);
    expect(env.CAPTCHA_PROVIDER).toBe('fake');

    const provider = createCaptchaProvider(env);
    expect(provider).toBeInstanceOf(FakeCaptchaProvider);
    await expect(provider.verify('fake-captcha-token')).resolves.toBe(true);
  });

  it('refuses a fake captcha in production', () => {
    expect(() =>
      createCaptchaProvider({ NODE_ENV: 'production', CAPTCHA_PROVIDER: 'fake' }),
    ).toThrow(/CAPTCHA_PROVIDER=fake is not allowed in NODE_ENV=production/);
  });

  it('refuses an unimplemented captcha provider', () => {
    expect(() =>
      createCaptchaProvider({ NODE_ENV: 'development', CAPTCHA_PROVIDER: 'recaptcha' }),
    ).toThrow(/CAPTCHA_PROVIDER=recaptcha is not implemented/);
  });
});
