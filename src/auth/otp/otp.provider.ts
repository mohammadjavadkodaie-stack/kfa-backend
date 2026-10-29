import type { Env } from '../../config/env';
import type { ProofPurpose } from './proof-token';

export interface OtpContext {
  readonly purpose: ProofPurpose;
}

/** A provider may verify remotely, or return a reference to a locally stored hash challenge. */
export interface OtpProvider {
  start(phoneE164: string, context: OtpContext): Promise<{ challengeRef: string | null }>;
  check(phoneE164: string, code: string, challengeRef: string | null): Promise<boolean>;
}

export const OTP_PROVIDER = Symbol('OTP_PROVIDER');

export class FakeOtpProvider implements OtpProvider {
  async start(_phoneE164: string, _context: OtpContext): Promise<{ challengeRef: string | null }> {
    return { challengeRef: null };
  }

  async check(_phoneE164: string, code: string, _challengeRef: string | null): Promise<boolean> {
    return code === '123456';
  }
}

/**
 * Builds the configured OTP provider, or refuses to boot.
 *
 * The fake adapter sends nothing and accepts one static code for every number,
 * so it must never serve production traffic. The environment validator already
 * rejects that combination; repeating the check here keeps the factory honest
 * for any wiring that does not go through `loadEnv`.
 */
export function createOtpProvider(env: Pick<Env, 'NODE_ENV' | 'OTP_PROVIDER'>): OtpProvider {
  if (env.OTP_PROVIDER !== 'fake') {
    throw new Error('Unsupported OTP_PROVIDER');
  }

  if (env.NODE_ENV === 'production') {
    throw new Error(
      'OTP_PROVIDER=fake is not allowed in NODE_ENV=production: it accepts a static code and sends no message',
    );
  }

  return new FakeOtpProvider();
}
