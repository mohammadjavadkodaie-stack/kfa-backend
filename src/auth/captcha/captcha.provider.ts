import type { Env } from '../../config/env';

export interface CaptchaProvider {
  verify(token: string, remoteIp?: string): Promise<boolean>;
}

export const CAPTCHA_PROVIDER = Symbol('CAPTCHA_PROVIDER');

/**
 * Captcha double for development and tests.
 *
 * `fake-captcha-pass` is the original test token and stays accepted for the
 * existing suites. `fake-captcha-token` is what the dev frontend sends; it is
 * accepted only when the provider was built for a non-production environment,
 * so a fake wired up in production still rejects it. The default is production,
 * which keeps an environment-less construction fail-closed.
 */
export class FakeCaptchaProvider implements CaptchaProvider {
  constructor(private readonly nodeEnv: Env['NODE_ENV'] = 'production') {}

  async verify(token: string, _remoteIp?: string): Promise<boolean> {
    if (token === 'fake-captcha-pass') return true;

    return this.nodeEnv !== 'production' && token === 'fake-captcha-token';
  }
}

/**
 * Builds the configured captcha provider, or refuses to boot.
 *
 * The fake accepts a static token without asking anybody, so it must never
 * serve production traffic. The environment validator already rejects that
 * combination; repeating the check here keeps the factory honest for any wiring
 * that does not go through `loadEnv`.
 */
export function createCaptchaProvider(
  env: Pick<Env, 'NODE_ENV' | 'CAPTCHA_PROVIDER'>,
): CaptchaProvider {
  if (env.CAPTCHA_PROVIDER !== 'fake') {
    throw new Error(`CAPTCHA_PROVIDER=${env.CAPTCHA_PROVIDER} is not implemented`);
  }

  if (env.NODE_ENV === 'production') {
    throw new Error(
      'CAPTCHA_PROVIDER=fake is not allowed in NODE_ENV=production: it accepts a static token',
    );
  }

  return new FakeCaptchaProvider(env.NODE_ENV);
}
