import { Inject, Injectable } from '@nestjs/common';
import {
  EMAIL_PROVIDER,
  type EmailProvider,
  type ReviewResultStatus,
} from '../auth/email/email.provider';
import {
  REVIEW_DECISION_INBOX,
  type ReviewDecisionInbox,
} from '../notifications/notifications.service';

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

/** What the in-site leg carries: the owner of the inbox row, and the outcome. */
export interface ReviewInSiteResult {
  readonly userId: string;
  readonly status: ReviewResultStatus;
}

export interface ReviewResultNotifier {
  sendResult(input: ReviewResultNotification): Promise<void>;
  /**
   * The in-site leg: one inbox row for the athlete, independent of the email.
   * Optional so a transport that only carries email can still satisfy the
   * interface; the caller then simply skips the inbox.
   */
  recordInSite?(input: ReviewInSiteResult): Promise<void>;
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
  constructor(
    @Inject(EMAIL_PROVIDER) private readonly email: EmailProvider,
    @Inject(REVIEW_DECISION_INBOX) private readonly inbox: ReviewDecisionInbox,
  ) {}

  async sendResult(input: ReviewResultNotification): Promise<void> {
    await this.email.sendReviewResult({
      to: input.to,
      status: input.status,
      reason: input.reason,
    });
  }

  /** Delegates to the notifications module, which owns the inbox rows. */
  recordInSite(input: ReviewInSiteResult): Promise<void> {
    return this.inbox.recordDecision(input.userId, input.status);
  }
}
