import { FakeCaptchaProvider } from './captcha.provider';

describe('FakeCaptchaProvider', () => {
  it('accepts only the development token', async () => {
    const provider = new FakeCaptchaProvider();
    await expect(provider.verify('fake-captcha-pass')).resolves.toBe(true);
    await expect(provider.verify('wrong-token')).resolves.toBe(false);
  });
});
