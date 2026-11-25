import type { Env } from '../../config/env';
import { ResendEmailProvider } from './resend-email.provider';
import type { EmailLocale } from './email.templates';

/** Why a code is being sent; the adapter may pick a different template per purpose. */
export type EmailCodePurpose =
  'register' | 'login_device' | 'password_reset' | 'email_change_new' | 'email_change_old';

/** A message without a code, sent after a security-relevant change. */
export type EmailNoticeKind =
  | 'password_changed'
  | 'email_changed'
  | 'new_device_login'
  | 'admin_granted'
  | 'failed_login_ip_surge'
  | 'backup_failed';

/** The outcome of a membership review, as the athlete sees it. */
export type ReviewResultStatus = 'APPROVED' | 'REJECTED';

export interface EmailCodeMessage {
  readonly to: string;
  readonly purpose: EmailCodePurpose;
  readonly code: string;
  readonly locale?: EmailLocale;
}

export interface EmailNoticeMessage {
  readonly to: string;
  readonly kind: EmailNoticeKind;
  readonly locale?: EmailLocale;
}

/** The decision only; `reason` is the reviewer's text and is sent for rejections. */
export interface ReviewResultMessage {
  readonly to: string;
  readonly status: ReviewResultStatus;
  readonly reason?: string | null;
  readonly locale?: EmailLocale;
}

/**
 * An already-encrypted backup file, attached to a message. Only the owner
 * mailboxes receive one; the plaintext dump never reaches an adapter.
 */
export interface BackupEmailMessage {
  readonly to: string;
  readonly filename: string;
  readonly content: Buffer;
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
  sendReviewResult(input: ReviewResultMessage): Promise<void>;
  /**
   * Delivers the nightly encrypted backup as an attachment. Best effort like
   * the rest of the contract: the caller decides what a failure means.
   */
  sendBackup(input: BackupEmailMessage): Promise<void>;
  /**
   * Present only on the fake adapter, so tests (and only tests) can read back
   * the static code. A real transport never exposes one.
   */
  readonly fixedCode?: string;
  /** Fake only: the review results it accepted, in order. */
  readonly reviewResults?: readonly ReviewResultMessage[];
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
  /** Kept so a suite can check what a decision sent, and in which language. */
  readonly reviewResults: ReviewResultMessage[] = [];
  /** Kept so a suite can check what a backup run delivered, and its size. */
  readonly backups: BackupEmailMessage[] = [];

  /** There is no transport in development, so the message stops here. */
  async sendCode(_input: EmailCodeMessage): Promise<void> {}

  /** Same for notices: nothing is delivered and nothing is written anywhere. */
  async sendNotice(_input: EmailNoticeMessage): Promise<void> {}

  /** Recorded only in memory: the fake is refused in production by the factory. */
  async sendReviewResult(input: ReviewResultMessage): Promise<void> {
    this.reviewResults.push(input);
  }

  /** Same for backups: the ciphertext stays in this array, nothing is sent. */
  async sendBackup(input: BackupEmailMessage): Promise<void> {
    this.backups.push(input);
  }
}

/**
 * Builds the configured email provider, or refuses to boot.
 *
 * `resend` is the real HTTPS adapter and refuses to build without its API key
 * and sender. The fake adapter accepts one static code for every address and
 * sends nothing, so it must never serve production traffic. The environment
 * validator already rejects that combination; repeating the check here keeps
 * the factory honest for any wiring that does not go through `loadEnv`.
 *
 * Any value the enum does not know fails loudly instead of silently falling
 * back to the fake.
 */
export function createEmailProvider(
  env: Pick<Env, 'NODE_ENV' | 'EMAIL_PROVIDER' | 'RESEND_API_KEY' | 'EMAIL_FROM'> &
    Partial<Pick<Env, 'EMAIL_CODE_TTL_SECONDS'>>,
): EmailProvider {
  if (env.EMAIL_PROVIDER === 'resend') {
    if (env.RESEND_API_KEY === undefined || env.EMAIL_FROM === undefined)
      throw new Error('RESEND_API_KEY and EMAIL_FROM are required for EMAIL_PROVIDER=resend');
    return new ResendEmailProvider(
      env.RESEND_API_KEY,
      env.EMAIL_FROM,
      env.EMAIL_CODE_TTL_SECONDS ?? 600,
    );
  }
  if (env.EMAIL_PROVIDER !== 'fake')
    throw new Error(`EMAIL_PROVIDER=${env.EMAIL_PROVIDER} is not implemented`);
  if (env.NODE_ENV === 'production') {
    throw new Error(
      'EMAIL_PROVIDER=fake is not allowed in NODE_ENV=production: it accepts a static code and sends no message',
    );
  }
  return new FakeEmailProvider();
}
