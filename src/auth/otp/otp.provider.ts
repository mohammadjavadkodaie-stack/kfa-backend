import type { Env } from '../../config/env';
import type { ProofPurpose } from './proof-token';

export interface OtpContext {
  readonly purpose: ProofPurpose;
}

/**
 * A plain message without a code. The only one so far warns the previous phone
 * that the account moved, and it carries the new number already masked so no
 * adapter can leak it into a log or a message by accident.
 */
export interface OtpNotice {
  readonly kind: 'phone_changed';
  readonly maskedPhone: string;
}

/** A provider may verify remotely, or return a reference to a locally stored hash challenge. */
export interface OtpProvider {
  start(phoneE164: string, context: OtpContext): Promise<{ challengeRef: string | null }>;
  check(phoneE164: string, code: string, challengeRef: string | null): Promise<boolean>;
  /** Best effort by contract: the caller decides what a failure means. */
  notify(phoneE164: string, notice: OtpNotice): Promise<void>;
}

export const OTP_PROVIDER = Symbol('OTP_PROVIDER');

export class FakeOtpProvider implements OtpProvider {
  async start(_phoneE164: string, _context: OtpContext): Promise<{ challengeRef: string | null }> {
    return { challengeRef: null };
  }

  async check(_phoneE164: string, code: string, _challengeRef: string | null): Promise<boolean> {
    return code === '123456';
  }

  /** There is no transport in development, so the notice stops here. */
  async notify(_phoneE164: string, _notice: OtpNotice): Promise<void> {}
}

/**
 * Production wiring: the phone/OTP identity flow is switched off. Every method
 * fails closed, so even a wiring mistake could never verify a code or send a
 * message; the routes themselves answer a generic 404 long before this is
 * reached (see `PhoneRoutesDisabledGuard`).
 */
class DisabledOtpProvider implements OtpProvider {
  async start(_phoneE164: string, _context: OtpContext): Promise<{ challengeRef: string | null }> {
    throw new Error('OTP flow is disabled in production');
  }

  async check(_phoneE164: string, _code: string, _challengeRef: string | null): Promise<boolean> {
    throw new Error('OTP flow is disabled in production');
  }

  async notify(_phoneE164: string, _notice: OtpNotice): Promise<void> {
    throw new Error('OTP flow is disabled in production');
  }
}

/**
 * Builds the configured OTP provider.
 *
 * Production never configures an adapter: the phone identity flow is disabled
 * there, the environment validator no longer requires `OTP_PROVIDER`, and the
 * disabled provider only exists so the DI graph stays complete while failing
 * closed. Outside production exactly one adapter exists, the fake one; any
 * other `OTP_PROVIDER` value is refused at wiring time, not at request time.
 */
export function createOtpProvider(env: Pick<Env, 'NODE_ENV' | 'OTP_PROVIDER'>): OtpProvider {
  if (env.NODE_ENV === 'production') {
    return new DisabledOtpProvider();
  }

  if (env.OTP_PROVIDER !== 'fake') {
    throw new Error('Unsupported OTP_PROVIDER');
  }

  return new FakeOtpProvider();
}
