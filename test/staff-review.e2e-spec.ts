import { ROLES_KEY } from '../src/auth/decorators/roles.decorator';
import { Role } from '../src/auth/roles';
import { STEPUP_WINDOW_MS, STEP_UP_REQUIRED_KEY } from '../src/auth/totp/step-up.guard';
import { StaffReviewController } from '../src/staff-review/staff-review.controller';
import type { AdminAccount } from './helpers/admin-harness';
import {
  createStaffReviewHarness,
  profileBody,
  type StaffReviewHarness,
} from './helpers/staff-review-harness';

/**
 * Stage 5.1b: the staff review routes over the real application.
 *
 * The stores are in memory, everything else is real: the guard stack, the global
 * pipe, the audit chain and the decision email. What is proved here is the
 * contract - who may reach the queue, what a page and a detail page contain,
 * that a decision is recorded once, and that its email cannot fail it.
 */

const QUEUE = '/staff/reviews';
const detail = (profileId: string) => `${QUEUE}/${profileId}`;
const approve = (profileId: string) => `${QUEUE}/${profileId}/approve`;
const reject = (profileId: string) => `${QUEUE}/${profileId}/reject`;

const UNAUTHORIZED = { statusCode: 401, message: 'Unauthorized' } as const;
const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;
const BAD_REQUEST = { statusCode: 400, message: 'Bad Request' } as const;
const NOT_FOUND = { statusCode: 404, message: 'Not Found' } as const;
const CONFLICT = { statusCode: 409, message: 'Conflict' } as const;
const STEP_UP_REQUIRED = { ...FORBIDDEN, code: 'step_up_required' } as const;
const SECOND_FACTOR_REQUIRED = { ...FORBIDDEN, code: 'second_factor_required' } as const;

/** The fields a queue row promises; a name or an address here would be a leak. */
const QUEUE_ITEM_FIELDS = ['documentCount', 'profileId', 'reviewStatus', 'submittedAt'];

/** Two envelopes of the same refusal differ only by request id. */
function withoutRequestId(body: { requestId?: string }): Record<string, unknown> {
  const { requestId: _requestId, ...rest } = body;

  return rest;
}

describe('Staff review routes (e2e)', () => {
  let harness: StaffReviewHarness;
  let staff: AdminAccount;

  beforeEach(async () => {
    harness = await createStaffReviewHarness('review');
    staff = await harness.staff();
  });

  afterEach(async () => {
    await harness.close();
  });

  describe('who may reach the queue', () => {
    it('refuses a request with no token', async () => {
      const response = await harness.anon(QUEUE);

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    });

    it('refuses an athlete, even with a valid token', async () => {
      const athlete = await harness.signUp(Role.ATHLETE);
      const response = await harness.get(QUEUE, athlete.token);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    });

    it('refuses a staff session that never proved a second factor', async () => {
      const gated = await harness.signUp(Role.ADMIN);
      const response = await harness.get(QUEUE, gated.token);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
    });

    it('declares the guard stack on every route', () => {
      const controller = StaffReviewController.prototype;
      const handlers = ['list', 'detail', 'approve', 'reject'] as const;

      for (const name of handlers) {
        expect(Reflect.getMetadata(ROLES_KEY, controller[name])).toEqual([Role.ADMIN, Role.OWNER]);
      }

      // Only the two decisions demand a fresh factor.
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, controller.approve)).toBe(true);
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, controller.reject)).toBe(true);
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, controller.list)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, controller.detail)).toBeUndefined();
    });
  });

  describe('GET /staff/reviews', () => {
    it('lists the oldest submission first, by id and count only', async () => {
      const older = '77777777-7777-4777-8777-777777777777';
      const newer = '88888888-8888-4888-8888-888888888888';

      harness.seedProfile(older, { submittedAt: new Date('2026-05-01T10:00:00.000Z') });
      harness.reviews.addDocument(older);
      harness.reviews.addDocument(older, { kind: 'MEDAL' });
      harness.seedProfile(newer, { submittedAt: new Date('2026-05-02T10:00:00.000Z') });

      const response = await harness.get(QUEUE, staff.token);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        items: [
          {
            profileId: older,
            reviewStatus: 'PENDING',
            submittedAt: '2026-05-01T10:00:00.000Z',
            documentCount: 2,
          },
          {
            profileId: newer,
            reviewStatus: 'PENDING',
            submittedAt: '2026-05-02T10:00:00.000Z',
            documentCount: 0,
          },
        ],
        nextCursor: null,
      });
      expect(Object.keys(response.body.items[0]).sort()).toEqual(QUEUE_ITEM_FIELDS);
    });

    it('pages with the cursor it hands back', async () => {
      const first = '99999999-9999-4999-8999-999999999999';
      const second = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

      harness.seedProfile(first, { submittedAt: new Date('2026-05-01T10:00:00.000Z') });
      harness.seedProfile(second, { submittedAt: new Date('2026-05-02T10:00:00.000Z') });

      const page = await harness.get(`${QUEUE}?limit=1`, staff.token);

      expect(page.status).toBe(200);
      expect(page.body.items).toHaveLength(1);
      expect(page.body.nextCursor).toBe(first);

      const cursor = String(page.body.nextCursor);
      const next = await harness.get(`${QUEUE}?limit=1&cursor=${cursor}`, staff.token);

      expect(next.body.items.map((item: { profileId: string }) => item.profileId)).toEqual([
        second,
      ]);
      expect(next.body.nextCursor).toBeNull();
    });

    it('filters by status and refuses a status the queue does not know', async () => {
      harness.seedProfile('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', { reviewStatus: 'APPROVED' });

      const approved = await harness.get(`${QUEUE}?status=APPROVED`, staff.token);

      expect(approved.status).toBe(200);
      expect(approved.body.items).toHaveLength(1);

      const draft = await harness.get(`${QUEUE}?status=DRAFT`, staff.token);

      expect(draft.status).toBe(400);
      expect(draft.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    });

    it('refuses a page size outside 1..50 and a cursor that is not an id', async () => {
      const tooBig = await harness.get(`${QUEUE}?limit=51`, staff.token);
      const badCursor = await harness.get(`${QUEUE}?cursor=nonsense`, staff.token);

      expect(tooBig.status).toBe(400);
      expect(badCursor.status).toBe(400);
    });
  });

  describe('GET /staff/reviews/:profileId', () => {
    it('shows the state and document metadata, and no personal data', async () => {
      const { account } = await harness.submittedAthlete();

      harness.reviews.recipients.set(account.userId, { email: 'ada@example.org' });

      const response = await harness.get(detail(account.userId), staff.token);
      const text = JSON.stringify(response.body);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        profileId: account.userId,
        reviewStatus: 'PENDING',
        submittedAt: expect.any(String),
        reviewedAt: null,
        rejectionReason: null,
        documents: [
          {
            id: expect.any(String),
            kind: 'NATIONAL_ID',
            sizeBytes: 1_024,
            createdAt: expect.any(String),
          },
        ],
      });
      // Neither the athlete's name nor their address is part of this answer.
      expect(text).not.toContain('Ada');
      expect(text).not.toContain('Lovelace');
      expect(text).not.toContain('ada@example.org');
    });

    it('answers one generic 404 for a draft and for an unknown profile', async () => {
      const athlete = await harness.signUp(Role.ATHLETE);

      harness.seedProfile(athlete.userId, { reviewStatus: 'DRAFT', submittedAt: null });

      const neverSubmitted = await harness.get(detail(athlete.userId), staff.token);
      const unknown = await harness.get(
        detail('cccccccc-cccc-4ccc-8ccc-cccccccccccc'),
        staff.token,
      );

      expect(neverSubmitted.status).toBe(404);
      expect(unknown.status).toBe(404);
      expect(neverSubmitted.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
      // Apart from the request id, the two answers are byte for byte the same.
      expect(withoutRequestId(unknown.body)).toEqual(withoutRequestId(neverSubmitted.body));
    });
  });

  describe('POST /staff/reviews/:profileId/approve', () => {
    it('approves a submitted profile, writes the trail and emails the athlete', async () => {
      const { account } = await harness.submittedAthlete();
      harness.reviews.recipients.set(account.userId, { email: 'ada@example.org' });

      const response = await harness.post(approve(account.userId), staff.token);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ reviewStatus: 'APPROVED', reviewedAt: expect.any(String) });
      expect(harness.rows('ATHLETE_PROFILE_APPROVED', account.userId)).toHaveLength(1);
      expect(harness.email.reviewResults).toEqual([
        { to: 'ada@example.org', status: 'APPROVED', reason: null },
      ]);

      const athlete = await harness.get('/athlete/profile', account.token);
      expect(athlete.body.reviewStatus).toBe('APPROVED');
    });

    it('refuses a decision from a session whose step-up is stale', async () => {
      const { account } = await harness.submittedAthlete();
      const stale = await harness.staff(Role.ADMIN, STEPUP_WINDOW_MS / 60_000 + 1);

      const response = await harness.post(approve(account.userId), stale.token);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ ...STEP_UP_REQUIRED, requestId: expect.any(String) });
      expect(harness.rows('ATHLETE_PROFILE_APPROVED', account.userId)).toHaveLength(0);
      expect(harness.email.reviewResults).toEqual([]);
      expect(harness.profiles.rows.get(account.userId)?.reviewStatus).toBe('PENDING');
    });

    it('answers 404 when the profile was never submitted', async () => {
      const response = await harness.post(
        approve('dddddddd-dddd-4ddd-8ddd-dddddddddddd'),
        staff.token,
      );

      expect(response.status).toBe(404);
      expect(response.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    });

    it('refuses a reviewer deciding on their own profile', async () => {
      harness.seedProfile(staff.userId);

      const response = await harness.post(approve(staff.userId), staff.token);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
      expect(harness.profiles.rows.get(staff.userId)?.reviewStatus).toBe('PENDING');
      expect(harness.rows('ATHLETE_PROFILE_APPROVED', staff.userId)).toHaveLength(0);
    });
  });

  describe('POST /staff/reviews/:profileId/reject', () => {
    it('records a rejection with the trimmed reason and sends it', async () => {
      const { account } = await harness.submittedAthlete();
      harness.reviews.recipients.set(account.userId, { email: 'ada@example.org' });

      const response = await harness.post(reject(account.userId), staff.token, {
        reason: '  the photo is blurry  ',
      });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ reviewStatus: 'REJECTED', reviewedAt: expect.any(String) });
      expect(harness.rows('ATHLETE_PROFILE_REJECTED', account.userId)[0]?.metadata).toEqual({
        reason: 'the photo is blurry',
      });
      expect(harness.email.reviewResults).toEqual([
        { to: 'ada@example.org', status: 'REJECTED', reason: 'the photo is blurry' },
      ]);
    });

    it('refuses a rejection without a usable reason, before anything is written', async () => {
      const { account } = await harness.submittedAthlete();

      const missing = await harness.post(reject(account.userId), staff.token, { reason: '   ' });
      const tooLong = await harness.post(reject(account.userId), staff.token, {
        reason: 'x'.repeat(501),
      });
      const noBody = await harness.post(reject(account.userId), staff.token);

      expect([missing.status, tooLong.status, noBody.status]).toEqual([400, 400, 400]);
      expect(harness.rows('ATHLETE_PROFILE_REJECTED', account.userId)).toHaveLength(0);
      expect(harness.profiles.rows.get(account.userId)?.reviewStatus).toBe('PENDING');
    });

    it('refuses a decision on a profile that is not pending any more', async () => {
      const { account } = await harness.submittedAthlete();

      const first = await harness.post(approve(account.userId), staff.token);
      const second = await harness.post(reject(account.userId), staff.token, {
        reason: 'changed my mind',
      });

      expect(first.status).toBe(200);
      expect(second.status).toBe(409);
      expect(second.body).toEqual({
        ...CONFLICT,
        code: 'profile_wrong_state',
        requestId: expect.any(String),
      });
      expect(harness.rows('ATHLETE_PROFILE_APPROVED', account.userId)).toHaveLength(1);
      expect(harness.rows('ATHLETE_PROFILE_REJECTED', account.userId)).toHaveLength(0);
    });

    it('lets a rejected athlete fix the profile and put it back in the queue', async () => {
      const { account } = await harness.submittedAthlete();

      const rejected = await harness.post(reject(account.userId), staff.token, {
        reason: 'the city is wrong',
      });
      expect(rejected.status).toBe(200);

      // Back to the athlete: the profile may be edited and submitted again.
      const body = profileBody({ city: 'Lahore' });
      const edited = await harness.put('/athlete/profile', account.token, body);
      const resubmitted = await harness.post('/athlete/profile/submit', account.token, body);

      expect(edited.status).toBe(200);
      expect(resubmitted.status).toBe(200);

      const detailView = await harness.get(detail(account.userId), staff.token);
      expect(detailView.body).toMatchObject({ reviewStatus: 'PENDING', rejectionReason: null });

      const approved = await harness.post(approve(account.userId), staff.token);
      expect(approved.status).toBe(200);
    });
  });

  describe('decision requests with no token', () => {
    it('are refused before any check runs', async () => {
      const response = await harness.post(approve('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'));

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    });
  });
});
