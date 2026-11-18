/**
 * Persistence boundary for the in-site inbox.
 *
 * Every operation is keyed by `userId`: the row id never leaves this layer and
 * no method accepts a filter a client could aim at somebody else's rows.
 */

/** The closed set of kinds the client's message catalog knows. */
export type NotificationKind =
  | 'profile_under_review'
  | 'profile_approved'
  | 'profile_rejected'
  | 'upload_status'
  | 'subscription_status';

/** Enum values only; the key set is closed per kind and there is no free text. */
export type NotificationParams = Readonly<Record<string, string>>;

/** One stored row. `readAt` is NULL until the owner marks the row read. */
export interface NotificationRecord {
  readonly id: string;
  readonly kind: NotificationKind;
  readonly params: NotificationParams;
  readonly createdAt: Date;
  readonly readAt: Date | null;
}

export interface NotificationPageQuery {
  /** One row more than this comes back, so the caller can tell whether a page follows. */
  readonly limit: number;
  /** The id of the previous page's last row. */
  readonly cursor?: string;
}

/** DI token so the Prisma implementation can be swapped in tests. */
export const NOTIFICATION_REPOSITORY = Symbol('NOTIFICATION_REPOSITORY');

export interface NotificationRepository {
  /**
   * Appends one row for one owner. The write is the whole effect: nothing is
   * read back, because the inbox never needs the row it just created.
   */
  create(userId: string, kind: NotificationKind, params: NotificationParams): Promise<void>;
  /**
   * Newest first. The cursor is the previous page's last id; the order is
   * completed by that same unique column, so a page never repeats or skips.
   */
  listForUser(userId: string, query: NotificationPageQuery): Promise<NotificationRecord[]>;
  /** Rows of one owner whose `read_at` is still NULL. */
  countUnread(userId: string): Promise<number>;
  /**
   * Marks the given ids of one owner read. Ids that belong to somebody else or
   * do not exist simply do not match: the count tells the truth, and the route
   * stays free of an existence oracle.
   */
  markRead(userId: string, ids: readonly string[], readAt: Date): Promise<number>;
  markAllRead(userId: string, readAt: Date): Promise<number>;
}
