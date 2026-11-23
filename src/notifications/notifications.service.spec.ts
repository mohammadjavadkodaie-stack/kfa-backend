import { BadRequestException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { InMemoryNotificationRepository } from '../../test/helpers/in-memory-notifications';
import { toNotificationView } from './notification.mapper';
import type { NotificationKind, NotificationParams } from './notification.repository';
import { NOTIFICATION_PAGE_SIZE, NotificationsService } from './notifications.service';

/**
 * The inbox service and its mapper without HTTP: the fixed page, the cursor,
 * the strict allowlist view (no extra key can ever ride along), the silent
 * no-op for a foreign id, and a decision row that carries nothing but the kind.
 */

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const EARLIER = new Date('2026-07-01T09:00:00.000Z');
const LATER = new Date('2026-07-02T09:00:00.000Z');

function seed(
  repository: InMemoryNotificationRepository,
  userId: string,
  kind: NotificationKind,
  overrides: { params?: NotificationParams; read?: boolean; createdAt?: Date } = {},
): string {
  const row = {
    id: randomUUID(),
    userId,
    kind,
    params: overrides.params ?? {},
    createdAt: overrides.createdAt ?? new Date(),
    readAt: overrides.read === true ? new Date() : null,
  };

  repository.rows.push(row);

  return row.id;
}

function harness(rows: number, kind: NotificationKind = 'profile_approved') {
  const repository = new InMemoryNotificationRepository();

  for (let index = 0; index < rows; index += 1) seed(repository, OWNER, kind);

  return { repository, service: new NotificationsService(repository) };
}

describe('notifications service', () => {
  it('lists only the caller rows, newest first', async () => {
    const { repository, service } = harness(0);

    seed(repository, OWNER, 'profile_approved', { createdAt: EARLIER });
    seed(repository, OTHER, 'profile_rejected', { createdAt: LATER });
    seed(repository, OWNER, 'profile_rejected', { createdAt: LATER });

    const page = await service.list(OWNER);

    expect(page.items.map((item) => item.type)).toEqual(['profile_rejected', 'profile_approved']);
  });

  it('serves one fixed page of twenty and walks the rest with the cursor', async () => {
    const { service } = harness(25);

    expect(NOTIFICATION_PAGE_SIZE).toBe(20);

    const first = await service.list(OWNER);

    expect(first.items).toHaveLength(20);
    expect(first.nextCursor).not.toBeNull();
    expect(first.unreadCount).toBe(25);

    const second = await service.list(OWNER, first.nextCursor ?? undefined);

    expect(second.items).toHaveLength(5);
    expect(second.nextCursor).toBeNull();
  });

  it('answers an empty page with no cursor and a zero count', async () => {
    const { service } = harness(0);

    await expect(service.list(OWNER)).resolves.toEqual({
      items: [],
      nextCursor: null,
      unreadCount: 0,
    });
  });
});
