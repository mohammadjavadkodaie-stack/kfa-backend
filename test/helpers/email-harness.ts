import {
  FakeEmailProvider as BaseFakeEmailProvider,
  type EmailCodeMessage,
  type EmailCodePurpose,
  type EmailNoticeMessage,
} from '../../src/auth/email/email.provider';
import { InMemoryEmailCodeStore, type EmailCodeStore } from '../../src/auth/email/email-code.store';

/**
 * Fixtures for the email identity flow.
 *
 * The code store is the in-memory implementation of the production contract and
 * the transport is the fake adapter, extended here so it keeps what it delivered
 * and a spec can read the code back instead of guessing it. Like the other test
 * helpers this file is framework-neutral: the specs own the assertions.
 */

/** The one code the fake transport accepts; a real adapter generates a random one. */
export const EMAIL_TEST_CODE = '123456';

export class FakeEmailProvider extends BaseFakeEmailProvider {
  override readonly fixedCode = EMAIL_TEST_CODE;

  /** Every code the transport was asked to deliver, in order. */
  readonly codes: EmailCodeMessage[] = [];
  /** Every notice the transport was asked to deliver, in order. */
  readonly notices: EmailNoticeMessage[] = [];

  override async sendCode(input: EmailCodeMessage): Promise<void> {
    this.codes.push({ ...input });
  }

  override async sendNotice(input: EmailNoticeMessage): Promise<void> {
    this.notices.push({ ...input });
  }

  /** Codes delivered to one address, optionally for one purpose only, oldest first. */
  codesFor(email: string, purpose?: EmailCodePurpose): string[] {
    return this.codes
      .filter(
        (message) => message.to === email && (purpose === undefined || message.purpose === purpose),
      )
      .map((message) => message.code);
  }

  /** The last code delivered to the address, or null when nothing was sent. */
  lastCode(email: string, purpose?: EmailCodePurpose): string | null {
    const delivered = this.codesFor(email, purpose);

    return delivered.length === 0 ? null : (delivered[delivered.length - 1] ?? null);
  }

  /** Forgets every delivered message, for a spec that counts from scratch. */
  clear(): void {
    this.codes.length = 0;
    this.notices.length = 0;
  }
}

export interface EmailHarness {
  readonly store: EmailCodeStore;
  readonly provider: FakeEmailProvider;
}

export function createEmailHarness(): EmailHarness {
  return { store: new InMemoryEmailCodeStore(), provider: new FakeEmailProvider() };
}
