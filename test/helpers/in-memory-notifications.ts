import { randomUUID } from 'node:crypto';
import type {
  NotificationKind,
  NotificationPageQuery,
  NotificationParams,
  NotificationRecord,
  NotificationRepository,
} from '../../src/notifications/notification.repository';

/** One stored row: exactly what the notifications table keeps. */
export interface StoredNotification {
  readonly id: string;
  readonly userId: string;
  readonly kind: NotificationKind;
  readonly params: NotificationParams;
  readonly createdAt: Date;
  /** Mutable so `markRead` can stamp it, like an UPDATE would. */
  readAt: Date | null;
}

/**
 * The notification table without PostgreSQL.
 *
 * The two predicates the Prisma implementation pushes into SQL - owner only,
 * newest first, completed by the unique id - are repeated here, so a suite can
 * prove that a foreign row is invisible and a cursor page resumes exactly.
 */
export class InMemoryNotificationRepository implements NotificationRepository {
  readonly rows: StoredNotification[] = [];
  /** Set to throw from one insert, to prove a failed write never fails a decision. */
  failCreateWith: Error | null = null;

  async create(userId: string, kind: NotificationKind, params: NotificationParams): Promise<void> {
    if (this.failCreateWith !== null) throw this.failCreateWith;

    this.rows.push({
      id: randomUUID(),
      userId,
      kind,
      params,
      createdAt: new Date(),
      readAt: null,
    });
  }

  async listForUser(
    userId: string,
    { limit, cursor }: NotificationPageQuery,
  ): Promise<NotificationRecord[]> {
    const owned = this.rows
      .filter((row) => row.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.id.localeCompare(a.id));

    if (cursor === undefined) return owned.slice(0, limit + 1);

    // Same semantics as Prisma's `cursor` + `skip 1`: resume after the handed
    // row; an unknown cursor simply yields an empty page.
    const after = owned.findIndex((row) => row.id === cursor);

    return after < 0 ? [] : owned.slice(after + 1, after + limit + 2);
  }

  async countUnread(userId: string): Promise<number> {
    return this.rows.filter((row) => row.userId === userId && row.readAt === null).length;
  }

  async markRead(userId: string, ids: readonly string[], readAt: Date): Promise<number> {
    let changed = 0;

    for (const row of this.rows) {
      if (row.userId === userId && row.readAt === null && ids.includes(row.id)) {
        row.readAt = readAt;
        changed += 1;
      }
    }

    return changed;
  }

  async markAllRead(userId: string, readAt: Date): Promise<number> {
    let changed = 0;

    for (const row of this.rows) {
      if (row.userId === userId && row.readAt === null) {
        row.readAt = readAt;
        changed += 1;
      }
    }

    return changed;
  }
}
