import type { Env } from '../../config/env';

/** Why a code is being sent; the adapter may pick a different template per purpose. */
export type EmailCodePurpose =
  'register' | 'login_device' | 'password_reset' | 'email_change_new' | 'email_change_old';

/** A message without a code, sent after a security-relevant change. */
export type EmailNoticeKind =
  'password_changed' | 'email_changed' | 'new_device_login' | 'admin_granted';

export interface EmailCodeMessage {
  readonly to: string;
  readonly purpose: EmailCodePurpose;
  readonly code: string;
}

export interface EmailNoticeMessage {
  readonly to: string;
  readonly kind: EmailNoticeKind;
}

/**
 * Transport for the email identity flow.
 *
 * Both methods are best effort by contract: the caller decides what a failure
 * means. Addresses are expected to be already normalised (`normalizeEmail`), so
 * an adapter never has to guess what the stored value looks like.
 */
export interface EmailProvider {
  sendCode(input: EmailCodeMessage): Promise<void>;
  sendNotice(input: EmailNoticeMessage): Promise<void>;
  /**
   * Present only on the fake adapter, so tests (and only tests) can read back
   * the static code. A real transport never exposes one.
   */
  readonly fixedCode?: string;
}

export const EMAIL_PROVIDER = Symbol('EMAIL_PROVIDER');

/**
 * Development/test adapter: no transport, no logging. It exposes the one static
 * code the fake accepts so a suite can assert on it, but it never prints the
 * address or the code - call sites are responsible for masking whatever they
 * log (`maskEmail`).
 */
export class FakeEmailProvider implements EmailProvider {
  readonly fixedCode = '123456';

  /** There is no transport in development, so the message stops here. */
  async sendCode(_input: EmailCodeMessage): Promise<void> {}

  /** Same for notices: nothing is delivered and nothing is written anywhere. */
  async sendNotice(_input: EmailNoticeMessage): Promise<void> {}
}

/**
 * Builds the configured email provider, or refuses to boot.
 *
 * The fake adapter accepts one static code for every address and sends nothing,
 * so it must never serve production traffic. The environment validator already
 * rejects that combination; repeating the check here keeps the factory honest
 * for any wiring that does not go through `loadEnv`.
 *
 * No real adapter exists yet: any other value fails loudly instead of silently
 * falling back to the fake.
 */
export function createEmailProvider(env: Pick<Env, 'NODE_ENV' | 'EMAIL_PROVIDER'>): EmailProvider {
  if (env.EMAIL_PROVIDER !== 'fake') {
    throw new Error(`EMAIL_PROVIDER=${env.EMAIL_PROVIDER} is not implemented`);
  }

  if (env.NODE_ENV === 'production') {
    throw new Error(
      'EMAIL_PROVIDER=fake is not allowed in NODE_ENV=production: it accepts a static code and sends no message',
    );
  }

  return new FakeEmailProvider();
}
