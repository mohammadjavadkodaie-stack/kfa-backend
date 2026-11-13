import type { Env } from '../../config/env';
import { TurnstileCaptchaProvider, type TurnstileLogLike } from './turnstile.provider';

/**
 * Captcha verifier used by every "start" flow (OTP, email code, password reset).
 *
 * Frontend contract: the widget's response token is sent in the existing
 * `captchaToken` field; the API shape does not change when the real verifier is
 * enabled.
 */
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
 * `turnstile` is the real Cloudflare adapter and refuses to build without its
 * secret. The fake accepts a static token without asking anybody, so it must
 * never serve production traffic. The environment validator already rejects
 * that combination; repeating the check here keeps the factory honest for any
 * wiring that does not go through `loadEnv`.
 *
 * `CAPTCHA_PROVIDER` is widened to `string` here so an unknown value fails at
 * boot instead of silently falling back to a verifier nobody chose.
 */
export type CaptchaProviderEnv = Pick<
  Env,
  'NODE_ENV' | 'TURNSTILE_SECRET_KEY' | 'TURNSTILE_EXPECTED_HOSTNAME'
> & {
  readonly CAPTCHA_PROVIDER: string;
};

export function createCaptchaProvider(
  env: CaptchaProviderEnv,
  logger?: TurnstileLogLike,
): CaptchaProvider {
  if (env.CAPTCHA_PROVIDER === 'turnstile') {
    if (env.TURNSTILE_SECRET_KEY === undefined || env.TURNSTILE_SECRET_KEY.length === 0) {
      throw new Error('TURNSTILE_SECRET_KEY is required for CAPTCHA_PROVIDER=turnstile');
    }

    return new TurnstileCaptchaProvider(
      env.TURNSTILE_SECRET_KEY,
      { expectedHostname: env.TURNSTILE_EXPECTED_HOSTNAME },
      fetch,
      logger,
    );
  }

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
