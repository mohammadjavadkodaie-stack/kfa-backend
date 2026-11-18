import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import type { ReviewResultStatus } from '../auth/email/email.provider';
import { toNotificationView, type NotificationView } from './notification.mapper';
import type { NotificationKind, NotificationRepository } from './notification.repository';
import { NOTIFICATION_REPOSITORY } from './notification.repository';

/**
 * The page the API serves. There is no `limit` parameter on purpose: the route
 * declares `cursor` only, so a caller cannot buy a bigger page, and 50 - the
 * hard maximum of the contract - is simply never reachable. The cursor walks
 * the rest of the inbox one fixed page at a time.
 */
export const NOTIFICATION_PAGE_SIZE = 20;

/** The read body may name at most this many ids; the client sends at most 100. */
export const MAX_MARK_READ_IDS = 100;

/** Exactly the envelope the client validates: `items`, `nextCursor`, `unreadCount`. */
export interface NotificationPage {
  readonly items: NotificationView[];
  readonly nextCursor: string | null;
  readonly unreadCount: number;
}

/** The read target: an explicit id list or everything, never both. */
export interface MarkReadInput {
  readonly ids?: readonly string[];
  readonly all?: true;
}

/**
 * The in-site leg of a review decision: one row for the athlete's own inbox.
 * The same outcome as the decision email, with no address and no text.
 */
export interface ReviewDecisionInbox {
  recordDecision(userId: string, status: ReviewResultStatus): Promise<void>;
}

/** DI token so the staff review module can reach the inbox without a concrete class. */
export const REVIEW_DECISION_INBOX = Symbol('REVIEW_DECISION_INBOX');

/** A decision maps onto one of the two profile kinds; there is no third. */
const KIND_BY_STATUS: Readonly<Record<ReviewResultStatus, NotificationKind>> = {
  APPROVED: 'profile_approved',
  REJECTED: 'profile_rejected',
};

/**
 * The owner's own inbox: newest first, one fixed page at a time, with the
 * unread count riding on every answer so the header badge needs no extra
 * endpoint and no polling.
 *
 * Every method is scoped by the verified principal. Marking somebody else's id
 * read is a silent no-op answered exactly like a mark of an id that does not
 * exist, so the route cannot be used to learn which ids exist.
 */
@Injectable()
export class NotificationsService implements ReviewDecisionInbox {
  constructor(
    @Inject(NOTIFICATION_REPOSITORY) private readonly repository: NotificationRepository,
  ) {}

  /** The producer's one call. `params` stays empty: the kind says it all. */
  async recordDecision(userId: string, status: ReviewResultStatus): Promise<void> {
    await this.repository.create(userId, KIND_BY_STATUS[status], {});
  }

  async list(userId: string, cursor?: string): Promise<NotificationPage> {
    const rows = await this.repository.listForUser(userId, {
      limit: NOTIFICATION_PAGE_SIZE,
      ...(cursor === undefined ? {} : { cursor }),
    });

    const page = rows.slice(0, NOTIFICATION_PAGE_SIZE);
    const last = page[page.length - 1];
    const items: NotificationView[] = [];

    for (const row of page) {
      // A row with a param value the catalog does not know is dropped, the
      // same way the client drops an unknown item.
      const view = toNotificationView(row);

      if (view !== null) items.push(view);
    }

    return {
      items,
      nextCursor: rows.length > page.length && last !== undefined ? last.id : null,
      unreadCount: await this.repository.countUnread(userId),
    };
  }

  async markRead(userId: string, input: MarkReadInput): Promise<{ unreadCount: number }> {
    const { ids, all } = input;

    // Exactly one target: a body with both fields, or with neither, is malformed.
    if ((ids === undefined) === (all === undefined)) throw new BadRequestException();

    const readAt = new Date();

    if (all === true) {
      await this.repository.markAllRead(userId, readAt);
    } else {
      await this.repository.markRead(userId, ids ?? [], readAt);
    }

    return { unreadCount: await this.repository.countUnread(userId) };
  }
}
