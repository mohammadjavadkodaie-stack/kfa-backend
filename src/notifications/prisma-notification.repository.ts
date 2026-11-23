import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import type {
  NotificationKind,
  NotificationPageQuery,
  NotificationParams,
  NotificationRecord,
  NotificationRepository,
} from './notification.repository';

/** Columns the repository reads back; the owner relation stays inside. */
const RECORD_FIELDS = {
  id: true,
  kind: true,
  params: true,
  createdAt: true,
  readAt: true,
} as const;

type NotificationRow = Prisma.NotificationGetPayload<{ select: typeof RECORD_FIELDS }>;

/** A Json column is typed loosely; this table's params are string values only. */
function toParams(value: Prisma.JsonValue): NotificationParams {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};

  const params: Record<string, string> = {};

  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') params[key] = entry;
  }

  return params;
}

function toRecord(row: NotificationRow): NotificationRecord {
  return {
    id: row.id,
    kind: row.kind,
    params: toParams(row.params),
    createdAt: row.createdAt,
    readAt: row.readAt,
  };
}

@Injectable()
export class PrismaNotificationRepository implements NotificationRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(userId: string, kind: NotificationKind, params: NotificationParams): Promise<void> {
    await this.prisma.notification.create({
      data: { userId, kind, params: params as Prisma.InputJsonObject },
    });
  }

  async listForUser(
    userId: string,
    { limit, cursor }: NotificationPageQuery,
  ): Promise<NotificationRecord[]> {
    const rows = await this.prisma.notification.findMany({
      where: { userId },
      // `createdAt` alone is not a key: the unique id completes the order, so a
      // cursor page resumes at exactly the row it was handed.
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      ...(cursor === undefined ? {} : { cursor: { id: cursor }, skip: 1 }),
      select: RECORD_FIELDS,
    });

    return rows.map(toRecord);
  }

  async countUnread(userId: string): Promise<number> {
    return this.prisma.notification.count({ where: { userId, readAt: null } });
  }

  /** One conditional statement: a foreign or unknown id is simply no row here. */
  async markRead(userId: string, ids: readonly string[], readAt: Date): Promise<number> {
    const result = await this.prisma.notification.updateMany({
      where: { userId, readAt: null, id: { in: [...ids] } },
      data: { readAt },
    });

    return result.count;
  }

  async markAllRead(userId: string, readAt: Date): Promise<number> {
    const result = await this.prisma.notification.updateMany({
      where: { userId, readAt: null },
      data: { readAt },
    });

    return result.count;
  }
}
