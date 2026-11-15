import { randomUUID } from 'node:crypto';
import type {
  EmailCodeMessage,
  EmailNoticeMessage,
  EmailProvider,
  ReviewResultMessage,
} from './email.provider';
import {
  buildCodeEmail,
  buildNoticeEmail,
  buildReviewResultEmail,
  escapeHtml,
  type EmailLocale,
} from './email.templates';

const RESEND_URL = 'https://api.resend.com/emails';
const TIMEOUT_MS = 8_000;

type FetchLike = typeof fetch;
type LogLike = {
  info: (data: object, message: string) => void;
  warn: (data: object, message: string) => void;
};

export class ResendEmailProvider implements EmailProvider {
  constructor(
    private readonly apiKey: string,
    private readonly from: string,
    private readonly ttlSeconds = 600,
    private readonly fetchFn: FetchLike = fetch,
    private readonly logger: LogLike = { info: () => undefined, warn: () => undefined },
  ) {}

  async sendCode(input: EmailCodeMessage): Promise<void> {
    const content = buildCodeEmail(input.purpose, input.code, input.locale, this.ttlSeconds);
    await this.send(input.to, content.subject, content.text, input.purpose);
  }

  async sendNotice(input: EmailNoticeMessage): Promise<void> {
    const content = buildNoticeEmail(input.kind, input.locale);
    await this.send(input.to, content.subject, content.text, input.kind);
  }

  /** A review decision is a single athlete-facing message about their own profile. */
  async sendReviewResult(input: ReviewResultMessage): Promise<void> {
    const content = buildReviewResultEmail(input.status, input.reason ?? null, input.locale);
    await this.send(input.to, content.subject, content.text, input.status.toLowerCase());
  }

  private async send(to: string, subject: string, text: string, purpose: string): Promise<void> {
    const masked = maskAddress(to);
    let lastFailure = 'network';
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
      try {
        const response = await this.fetchFn(RESEND_URL, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': randomUUID(),
          },
          body: JSON.stringify({
            from: this.from,
            to: [to],
            subject,
            text,
            html: `<p>${escapeHtml(text).replace(/\n/gu, '<br>')}</p>`,
          }),
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (response.ok) {
          this.logger.info({ purpose, status: response.status }, 'resend email sent');
          return;
        }
        lastFailure =
          response.status === 429
            ? '429'
            : response.status >= 500
              ? '5xx'
              : String(response.status);
        if (response.status !== 429 && response.status < 500) break;
      } catch (error) {
        clearTimeout(timeout);
        lastFailure =
          error instanceof DOMException && error.name === 'AbortError' ? 'timeout' : 'network';
      }
      if (attempt === 0) await delay(50);
    }
    this.logger.warn({ purpose, address: masked, failure: lastFailure }, 'resend email failed');
    throw new Error(`resend email delivery failed (${lastFailure})`);
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function maskAddress(address: string): string {
  const at = address.indexOf('@');
  return at <= 1
    ? `***${at >= 0 ? address.slice(at) : ''}`
    : `${address[0]}***${address.slice(at)}`;
}

export type { EmailLocale };
