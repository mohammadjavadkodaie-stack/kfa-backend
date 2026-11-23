import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { FakeRateLimit } from './helpers/auth-service-harness';
import { createAdminHarness, type AdminHarness } from './helpers/admin-harness';
import { InMemoryNotificationRepository } from './helpers/in-memory-notifications';
import { createStaffReviewHarness, type StaffReviewHarness } from './helpers/staff-review-harness';
import type {
  NotificationKind,
  NotificationParams,
} from '../src/notifications/notification.repository';
import type { RateLimitService } from '../src/rate-limit/rate-limit.service';

/**
 * Stage 6: the in-site notifications routes over the real application.
 *
 * The stores are in memory, everything else is real: the guard stack, the pipe,
 * the limiter wiring and the review producer. What must hold:
 *
 * - the inbox is owner-scoped end to end - a list and a mark-read see exactly
 *   the caller's rows and nothing of anybody else's,
 * - a foreign id is answered exactly like a nonexistent one, so the route
 *   cannot be used to learn which ids exist,
 * - the envelope carries no field beyond items, nextCursor and unreadCount,
 *   the shapes the frontend validates strictly,
 * - a review decision lands in the athlete's inbox, and a failed write never
 *   fails the decision,
 * - both routes answer the shared 429 envelope with Retry-After.
 */

const OTHER_USER = '22222222-2222-4222-8222-222222222222';

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

describe('Notifications routes (e2e)', () => {
  let base: AdminHarness;
  let repository: InMemoryNotificationRepository;
  let token: string;
  let athleteUserId: string;

  beforeAll(async () => {
    repository = new InMemoryNotificationRepository();
    base = await createAdminHarness('notif', { notificationRepository: repository });

    const account = await base.signUp('ATHLETE' as never);

    token = account.token;
    athleteUserId = account.userId;

    seed(repository, account.userId, 'profile_approved');
    seed(repository, account.userId, 'upload_status', {
      params: { status: 'approved' },
      createdAt: new Date(1),
    });
    seed(repository, account.userId, 'profile_rejected', { createdAt: new Date(0) });
    seed(repository, OTHER_USER, 'profile_approved');
  });

  afterAll(async () => {
    await base.close();
  });

  const server = () => request(base.app.getHttpServer());
  const read = (body: object) =>
    server().post('/notifications/read').set('Authorization', `Bearer ${token}`).send(body);
  const list = (query?: object) => {
    const call = server().get('/notifications').set('Authorization', `Bearer ${token}`);

    return query === undefined ? call : call.query(query);
  };

  it('refuses an anonymous list', async () => {
    await server().get('/notifications').expect(401);
  });

  it('lists only the caller rows, newest first, in the strict envelope', async () => {
    const response = await list().expect(200);

    expect(Object.keys(response.body).sort()).toEqual(['items', 'nextCursor', 'unreadCount']);
    expect(response.body.unreadCount).toBe(3);
    expect(response.body.nextCursor).toBeNull();
    expect(response.body.items.map((item: { type: string }) => item.type)).toEqual([
      'profile_approved',
      'upload_status',
      'profile_rejected',
    ]);
    expect(Object.keys(response.body.items[0]).sort()).toEqual(['createdAt', 'id', 'read', 'type']);
    expect(Object.keys(response.body.items[1]).sort()).toEqual([
      'createdAt',
      'id',
      'params',
      'read',
      'type',
    ]);
    expect(response.body.items[1].params).toEqual({ status: 'approved' });
  });

  it('refuses an unknown query parameter and an oversized cursor', async () => {
    await list({ limit: 50 }).expect(400);
    await list({ cursor: 'x'.repeat(513) }).expect(400);
  });

  it('walks the inbox with the cursor it handed out', async () => {
    for (let index = 0; index < 25; index += 1) {
      seed(repository, athleteUserId, 'profile_under_review', {
        createdAt: new Date(Date.UTC(2026, 0, 1, 0, index)),
      });
    }

    const first = await list().expect(200);

    expect(first.body.items).toHaveLength(20);
    expect(typeof first.body.nextCursor).toBe('string');

    const second = await list({ cursor: first.body.nextCursor }).expect(200);

    expect(second.body.items).toHaveLength(8);
    expect(second.body.nextCursor).toBeNull();
    expect(second.body.unreadCount).toBe(28);
  });

  it('marks one own id read and reports the new count', async () => {
    const ownId = seed(repository, athleteUserId, 'profile_approved');

    // 3 seeded + 25 paged + this one: the count drops only for this caller.
    await read({ ids: [ownId] })
      .expect(200)
      .expect({ unreadCount: 28 });

    expect(repository.rows.find((row) => row.id === ownId)?.readAt).not.toBeNull();
  });

  it('answers a foreign id exactly like a nonexistent one', async () => {
    const foreignId = seed(repository, OTHER_USER, 'profile_approved');

    const foreign = await read({ ids: [foreignId] }).expect(200);
    const missing = await read({ ids: [randomUUID()] }).expect(200);

    expect(foreign.body).toEqual(missing.body);
    expect(foreign.body.unreadCount).toBe(28);
    expect(repository.rows.find((row) => row.id === foreignId)?.readAt).toBeNull();
  });

  it('refuses malformed read bodies', async () => {
    for (const body of [
      {},
      { ids: [] },
      { ids: ['not-a-uuid'] },
      { ids: [randomUUID(), 'nope'] },
      { all: false },
      { ids: [randomUUID()], all: true },
      { ids: [randomUUID()], extra: 1 },
    ]) {
      await read(body).expect(400);
    }
  });

  it('marks everything read and stays at zero', async () => {
    await read({ all: true }).expect(200).expect({ unreadCount: 0 });
    await read({ all: true }).expect(200).expect({ unreadCount: 0 });
  });
});

describe('Notifications rate limits (e2e)', () => {
  it('answers the shared 429 envelope with Retry-After once the budget is spent', async () => {
    const limiter = new FakeRateLimit();
    const harness = await createAdminHarness('notiflimit', {
      rateLimit: limiter as unknown as RateLimitService,
    });

    try {
      const account = await harness.signUp('ATHLETE' as never);

      limiter.deny(42);

      const refusedList = await request(harness.app.getHttpServer())
        .get('/notifications')
        .set('Authorization', `Bearer ${account.token}`);

      const refusedRead = await request(harness.app.getHttpServer())
        .post('/notifications/read')
        .set('Authorization', `Bearer ${account.token}`)
        .send({ all: true });

      for (const refused of [refusedList, refusedRead]) {
        expect(refused.status).toBe(429);
        expect(refused.headers['retry-after']).toBe('42');
        expect(refused.body).toEqual({
          statusCode: 429,
          message: 'Too Many Requests',
          requestId: expect.any(String),
        });
      }
    } finally {
      await harness.close();
    }
  });
});

describe('Review decisions produce notifications (e2e)', () => {
  let harness: StaffReviewHarness;
  let staffToken: string;

  beforeAll(async () => {
    harness = await createStaffReviewHarness('notifproducer');

    staffToken = (await harness.staff()).token;
  });

  afterAll(async () => {
    await harness.close();
  });

  it('creates exactly one inbox row per decision, next to the email', async () => {
    const approved = await harness.submittedAthlete();

    harness.reviews.recipients.set(approved.account.userId, { email: 'ada@example.org' });

    await harness.post(`/staff/reviews/${approved.profile.userId}/approve`, staffToken).expect(200);

    const rows = harness.notifications.rows.filter((row) => row.userId === approved.account.userId);

    expect(rows.map((row) => row.kind)).toEqual(['profile_approved']);
    expect(rows.every((row) => Object.keys(row.params).length === 0)).toBe(true);
    expect(harness.email.reviewResults).toHaveLength(1);

    // The athlete reads the decision in the app.
    const inbox = await request(harness.app.getHttpServer())
      .get('/notifications')
      .set('Authorization', `Bearer ${approved.account.token}`)
      .expect(200);

    expect(inbox.body.items).toHaveLength(1);
    expect(inbox.body.items[0].type).toBe('profile_approved');
    expect(inbox.body.unreadCount).toBe(1);

    const rejected = await harness.submittedAthlete();

    harness.reviews.recipients.set(rejected.account.userId, { email: 'ada@example.org' });

    await harness
      .post(`/staff/reviews/${rejected.profile.userId}/reject`, staffToken, {
        reason: 'The medal record could not be verified.',
      })
      .expect(200);

    expect(
      harness.notifications.rows
        .filter((row) => row.userId === rejected.account.userId)
        .map((row) => row.kind),
    ).toEqual(['profile_rejected']);
    expect(harness.email.reviewResults).toHaveLength(2);
  });

  it('never lets a failed notification write fail the decision', async () => {
    const athlete = await harness.submittedAthlete();

    harness.reviews.recipients.set(athlete.account.userId, { email: 'ada@example.org' });

    harness.notifications.failCreateWith = new Error('the inbox is down');

    try {
      await harness
        .post(`/staff/reviews/${athlete.profile.userId}/approve`, staffToken)
        .expect(200);
    } finally {
      harness.notifications.failCreateWith = null;
    }

    // The decision email went out and the profile moved; only the row is missing.
    expect(harness.email.reviewResults).toHaveLength(3);
    expect(harness.profiles.rows.get(athlete.account.userId)?.reviewStatus).toBe('APPROVED');
  });
});
