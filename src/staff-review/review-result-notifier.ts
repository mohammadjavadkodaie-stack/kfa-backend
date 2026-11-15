import { Inject, Injectable } from '@nestjs/common';
import {
  EMAIL_PROVIDER,
  type EmailProvider,
  type ReviewResultStatus,
} from '../auth/email/email.provider';

/**
 * What a decision sends: one address, the outcome, and the reviewer's reason on
 * a rejection. Nothing about who reviewed it, and nothing about the documents.
 *
 * There is no language field because there is nothing to read one from: the
 * account has no stored preference, so the transport renders the default
 * language of the templates.
 */
export interface ReviewResultNotification {
  readonly to: string;
  readonly status: ReviewResultStatus;
  readonly reason: string | null;
}

export interface ReviewResultNotifier {
  sendResult(input: ReviewResultNotification): Promise<void>;
}

/** DI token so the transport fake can be swapped in tests. */
export const REVIEW_RESULT_NOTIFIER = Symbol('REVIEW_RESULT_NOTIFIER');

/**
 * The decision email. Delivery is best effort and lives after the decision has
 * been committed: a transport failure is reported by the caller, never turned
 * into a failed decision.
 */
@Injectable()
export class EmailReviewResultNotifier implements ReviewResultNotifier {
  constructor(@Inject(EMAIL_PROVIDER) private readonly email: EmailProvider) {}

  async sendResult(input: ReviewResultNotification): Promise<void> {
    await this.email.sendReviewResult({
      to: input.to,
      status: input.status,
      reason: input.reason,
    });
  }
}
