export interface CaptchaProvider {
  verify(token: string, remoteIp?: string): Promise<boolean>;
}

export const CAPTCHA_PROVIDER = Symbol('CAPTCHA_PROVIDER');

export class FakeCaptchaProvider implements CaptchaProvider {
  async verify(token: string, _remoteIp?: string): Promise<boolean> {
    return token === 'fake-captcha-pass';
  }
}
