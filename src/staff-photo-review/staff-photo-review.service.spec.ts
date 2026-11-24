import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import type { ProfilePhotoStatus } from '../athlete/photos/profile-photo.repository';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import type { PrismaService } from '../database/prisma.service';
import { StaffPhotoReviewController } from './staff-photo-review.controller';
import { MAX_PHOTO_REJECTION_REASON_LENGTH } from './staff-photo-review.dto';
import type {
  PendingPhotoRow,
  PhotoReviewDecision,
  PhotoReviewTarget,
  PhotoTakedown,
  ReportedPhotoRow,
  StaffPhotoReviewRepository,
} from './staff-photo-review.repository';
import {
  STAFF_PHOTO_REVIEW_AUDIT_ACTIONS,
  StaffPhotoReviewService,
} from './staff-photo-review.service';

/**
 * The staff photo moderation queue without HTTP.
 *
 * What is proved here is the part a suite can only see below the controller: the
 * default page and its cursor, the single conditional UPDATE, the self-review
 * refusal, the audit row sharing the decision's transaction, and the guard
 * markers the global stack reads.
 */

const STAFF_ID = '11111111-1111-4111-8111-111111111111';
const PROFILE_ID = '22222222-2222-4222-8222-222222222222';
const OWNER_ID = '44444444-4444-4444-8444-444444444444';
const REQUEST_ID = 'req-photo-review';

/** The request facts the handler passes down; the audit writer hashes the IP. */
const CONTEXT: AccessPolicyContext = { requestId: REQUEST_ID, ip: '203.0.113.9' };

/** Fixed clock: only the compared value matters, never the real time. */
const NOW = new Date('2026-08-01T10:15:00.000Z');
const EARLIER = new Date('2026-07-01T08:00:00.000Z');
const MIDDLE = new Date('2026-07-02T08:00:00.000Z');
const LATEST = new Date('2026-07-03T08:00:00.000Z');

const reviewer: PolicySubject = { id: STAFF_ID, role: Role.ADMIN };

/** Exactly what a queue row may carry: no key, no digest, no review columns. */
const QUEUE_ITEM_FIELDS = [
  'athleteProfileId',
  'caption',
  'contentType',
  'createdAt',
  'id',
  'sizeBytes',
];

/** One stored row, plus what a decision writes to it. */
interface StoredPhoto extends PendingPhotoRow {
  readonly ownerUserId: string;
  status: ProfilePhotoStatus;
  reviewedAt: Date | null;
  reviewedById: string | null;
}

/** The three fields a decision writes, captured so a rollback can put them back. */
interface PhotoRowState {
  status: ProfilePhotoStatus;
  reviewedAt: Date | null;
  reviewedById: string | null;
}

/** The `profile_photos` table without PostgreSQL: the predicate is repeated here. */
class InMemoryStaffPhotoReview implements StaffPhotoReviewRepository {
  readonly rows = new Map<string, StoredPhoto>();
  /** Every decision attempt, in order, so a refusal can be shown to write nothing. */
  readonly decisions: {
    photoId: string;
    decision: PhotoReviewDecision;
    tx: Prisma.TransactionClient | undefined;
  }[] = [];
  /** Every queue read, with what it asked for, in order. */
  readonly queueReads: { limit: number; cursor: string | undefined }[] = [];
  /** Every takedown attempt, in order, so a refusal can be shown to write nothing. */
  readonly takedowns: {
    photoId: string;
    takedown: PhotoTakedown;
    tx: Prisma.TransactionClient | undefined;
  }[] = [];
  /** The `photo_reports` table, by photo: one entry per report's timestamp. */
  readonly reports = new Map<string, Date[]>();
  /** Every reported-list read, with what it asked for, in order. */
  readonly reportedReads: { limit: number; offset: number }[] = [];

  seed(id: string, overrides: Partial<StoredPhoto> = {}): StoredPhoto {
    const row: StoredPhoto = {
      id,
      athleteProfileId: PROFILE_ID,
      caption: 'First meet',
      contentType: 'image/jpeg',
      sizeBytes: 2_048,
      createdAt: EARLIER,
      ownerUserId: OWNER_ID,
      status: 'PENDING',
      reviewedAt: null,
      reviewedById: null,
      ...overrides,
    };

    this.rows.set(id, row);

    return row;
  }

  async listPending(limit: number, cursor?: string): Promise<PendingPhotoRow[]> {
    this.queueReads.push({ limit, cursor });

    // Same predicate and total order as the query: PENDING only, oldest first,
    // the id breaking a tie.
    const pending = [...this.rows.values()]
      .filter((row) => row.status === 'PENDING')
      .sort(
        (left, right) =>
          left.createdAt.getTime() - right.createdAt.getTime() || left.id.localeCompare(right.id),
      );

    // The page resumes after the cursor row; a cursor that is gone yields nothing.
    if (cursor !== undefined) {
      const index = pending.findIndex((row) => row.id === cursor);

      return index < 0 ? [] : pending.slice(index + 1, index + 1 + limit + 1);
    }

    return pending.slice(0, limit + 1);
  }

  async findForReview(photoId: string): Promise<PhotoReviewTarget | null> {
    const row = this.rows.get(photoId);

    return row === undefined
      ? null
      : {
          id: row.id,
          athleteProfileId: row.athleteProfileId,
          ownerUserId: row.ownerUserId,
          status: row.status,
        };
  }

  async applyDecision(
    photoId: string,
    decision: PhotoReviewDecision,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    this.decisions.push({ photoId, decision, tx });

    const row = this.rows.get(photoId);

    // The conditional UPDATE: a photo leaves PENDING exactly once.
    if (row === undefined || row.status !== 'PENDING') return 0;

    row.status = decision.status;
    row.reviewedAt = decision.reviewedAt;
    row.reviewedById = decision.reviewedById;

    return 1;
  }

  /** Adds one report row for a photo, as a user's POST would. */
  report(photoId: string, at: Date = LATEST): void {
    this.reports.set(photoId, [...(this.reports.get(photoId) ?? []), at]);
  }

  async takeDown(
    photoId: string,
    takedown: PhotoTakedown,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    this.takedowns.push({ photoId, takedown, tx });

    const row = this.rows.get(photoId);

    // The conditional UPDATE: a photo leaves PENDING or APPROVED exactly once.
    if (row === undefined || (row.status !== 'PENDING' && row.status !== 'APPROVED')) return 0;

    row.status = 'REMOVED';
    row.reviewedAt = takedown.reviewedAt;
    row.reviewedById = takedown.reviewedById;

    return 1;
  }

  async listReported(limit: number, offset: number): Promise<ReportedPhotoRow[]> {
    this.reportedReads.push({ limit, offset });

    // APPROVED photos that carry at least one report, newest activity first, with
    // the count and the newest report - and no reporter in sight.
    return [...this.rows.values()]
      .flatMap((row) => {
        const reportedAt = this.reports.get(row.id);

        if (row.status !== 'APPROVED' || reportedAt === undefined) return [];

        const newest = Math.max(...reportedAt.map((at) => at.getTime()));

        return [{ ...row, reportCount: reportedAt.length, lastReportedAt: new Date(newest) }];
      })
      .sort(
        (left, right) =>
          right.lastReportedAt.getTime() - left.lastReportedAt.getTime() ||
          left.id.localeCompare(right.id),
      )
      .slice(offset, offset + limit + 1);
  }

  snapshot(): Map<string, PhotoRowState> {
    const copy = new Map<string, PhotoRowState>();

    // Field values, not the rows: an UPDATE mutates the row in place, so only a
    // value copy can be written back over it.
    this.rows.forEach((row, id) =>
      copy.set(id, {
        status: row.status,
        reviewedAt: row.reviewedAt,
        reviewedById: row.reviewedById,
      }),
    );

    return copy;
  }

  restore(snapshot: Map<string, PhotoRowState>): void {
    snapshot.forEach((state, id) => {
      const row = this.rows.get(id);

      if (row === undefined) return;

      row.status = state.status;
      row.reviewedAt = state.reviewedAt;
      row.reviewedById = state.reviewedById;
    });
  }
}

/** The one thing the service needs from Prisma: an interactive transaction. */
class FakePrisma {
  readonly options: unknown[] = [];

  constructor(private readonly photos: InMemoryStaffPhotoReview) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    this.options.push(options);

    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;
    const before = this.photos.snapshot();

    try {
      return await run(tx);
    } catch (error) {
      // A throw from the callback discards every write, exactly as the client does.
      this.photos.restore(before);

      throw error;
    }
  }
}

class FailingAudit extends FakeAudit {
  override async record(): Promise<void> {
    throw new Error('audit chain is unavailable');
  }
}

/** Warnings are the only thing a refused or failed trail may leave behind. */
class QuietLogger {
  readonly warns: { payload: unknown; message: string }[] = [];

  warn(payload: unknown, message = ''): void {
    this.warns.push({ payload, message });
  }

  messages(): string[] {
    return this.warns.map((entry) => entry.message);
  }
}

const PHOTO_ID = '88888888-8888-4888-8888-888888888888';
const SECOND_PHOTO_ID = '99999999-9999-4999-8999-999999999999';
const THIRD_PHOTO_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

interface Handles {
  readonly service: StaffPhotoReviewService;
  readonly photos: InMemoryStaffPhotoReview;
  readonly audit: FakeAudit;
  readonly logger: QuietLogger;
  readonly prisma: FakePrisma;
}

function createService(
  options: { audit?: FakeAudit; photos?: InMemoryStaffPhotoReview } = {},
): Handles {
  const photos = options.photos ?? new InMemoryStaffPhotoReview();
  const audit = options.audit ?? new FakeAudit();
  const logger = new QuietLogger();
  const prisma = new FakePrisma(photos);
  const service = new StaffPhotoReviewService(
    prisma as unknown as PrismaService,
    photos,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    () => NOW,
  );

  return { service, photos, audit, logger, prisma };
}

/** The error a refused call throws, proved to be the expected class. */
async function refusalOf(call: Promise<unknown>, type: new () => Error): Promise<Error> {
  try {
    await call;
  } catch (error) {
    if (error instanceof type) return error;

    throw error;
  }

  throw new Error('expected the call to be refused');
}

/** The generic message a refusal carries: no ids, no field names, no reason. */
function messageOf(error: Error): string {
  const response = (error as unknown as { getResponse: () => { message?: string } }).getResponse();

  return response.message ?? '';
}

describe('StaffPhotoReviewService', () => {
  describe('listQueue', () => {
    it('defaults to one page of pending photos, oldest first', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { createdAt: EARLIER });
      photos.seed(SECOND_PHOTO_ID, { createdAt: LATEST });

      const page = await service.listQueue({});

      expect(photos.queueReads).toEqual([{ limit: 20, cursor: undefined }]);
      expect(page.items.map((item) => item.id)).toEqual([PHOTO_ID, SECOND_PHOTO_ID]);
      expect(page.items[0]).toEqual({
        id: PHOTO_ID,
        athleteProfileId: PROFILE_ID,
        caption: 'First meet',
        contentType: 'image/jpeg',
        sizeBytes: 2_048,
        createdAt: EARLIER.toISOString(),
      });
      // A key, a digest or a view link here would be a leak.
      expect(Object.keys(page.items[0] ?? {}).sort()).toEqual(QUEUE_ITEM_FIELDS);
      expect(page.nextCursor).toBeNull();
    });

    it('lists nothing that a reviewer already decided', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID);
      photos.seed(SECOND_PHOTO_ID, { status: 'APPROVED', reviewedAt: EARLIER });

      const page = await service.listQueue({});

      expect(page.items.map((item) => item.id)).toEqual([PHOTO_ID]);
    });

    it('stops at the requested size and hands back the last id as the cursor', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { createdAt: EARLIER });
      photos.seed(SECOND_PHOTO_ID, { createdAt: MIDDLE });
      photos.seed(THIRD_PHOTO_ID, { createdAt: LATEST });

      const first = await service.listQueue({ limit: 1 });

      expect(first.items.map((item) => item.id)).toEqual([PHOTO_ID]);
      expect(first.nextCursor).toBe(PHOTO_ID);

      const second = await service.listQueue({ limit: 2, cursor: PHOTO_ID });

      expect(photos.queueReads[1]).toEqual({ limit: 2, cursor: PHOTO_ID });
      expect(second.items.map((item) => item.id)).toEqual([SECOND_PHOTO_ID, THIRD_PHOTO_ID]);
      expect(second.nextCursor).toBeNull();
    });
  });

  describe('decide - approve', () => {
    it('writes the outcome, the reviewer and the clock in one statement', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID);

      const result = await service.decide(reviewer, PHOTO_ID, { status: 'APPROVED' }, CONTEXT);

      expect(result).toEqual({ status: 'APPROVED', reviewedAt: NOW.toISOString() });
      expect(row.status).toBe('APPROVED');
      expect(row.reviewedAt).toEqual(NOW);
      expect(row.reviewedById).toBe(STAFF_ID);
      expect(audit.records).toEqual([
        {
          action: STAFF_PHOTO_REVIEW_AUDIT_ACTIONS.APPROVED,
          actorId: STAFF_ID,
          actorRole: Role.ADMIN,
          targetType: 'profile_photo',
          targetId: PHOTO_ID,
          requestId: REQUEST_ID,
          ip: CONTEXT.ip,
          metadata: { photoId: PHOTO_ID, athleteProfileId: PROFILE_ID, status: 'APPROVED' },
        },
      ]);
      // The trail row joined the same transaction as the UPDATE.
      expect(audit.transactions[0]).toBe(photos.decisions[0]?.tx);
      expect(photos.decisions[0]?.tx).toBeDefined();
    });
  });

  describe('decide - reject', () => {
    it('keeps the reason in the audit metadata only', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID);

      await service.decide(
        reviewer,
        PHOTO_ID,
        { status: 'REJECTED', reason: '  the photo is blurry  ' },
        CONTEXT,
      );

      expect(row.status).toBe('REJECTED');
      expect(row.reviewedById).toBe(STAFF_ID);
      // The photo row holds no reason column; the reviewer's words exist once.
      expect(Object.keys(row)).not.toContain('reason');
      expect(audit.records[0]).toMatchObject({
        action: STAFF_PHOTO_REVIEW_AUDIT_ACTIONS.REJECTED,
        targetId: PHOTO_ID,
      });
      expect(audit.records[0]?.metadata).toEqual({
        photoId: PHOTO_ID,
        athleteProfileId: PROFILE_ID,
        status: 'REJECTED',
        reason: 'the photo is blurry',
      });
    });

    it('accepts no reason at all, and a reason of spaces is no reason', async () => {
      const { service, photos, audit } = createService();

      photos.seed(PHOTO_ID);
      photos.seed(SECOND_PHOTO_ID);

      await service.decide(reviewer, PHOTO_ID, { status: 'REJECTED' }, CONTEXT);
      await service.decide(
        reviewer,
        SECOND_PHOTO_ID,
        { status: 'REJECTED', reason: '   ' },
        CONTEXT,
      );

      expect(audit.records[0]?.metadata).toEqual({
        photoId: PHOTO_ID,
        athleteProfileId: PROFILE_ID,
        status: 'REJECTED',
      });
      expect(audit.records[1]?.metadata).toEqual({
        photoId: SECOND_PHOTO_ID,
        athleteProfileId: PROFILE_ID,
        status: 'REJECTED',
      });
    });

    it('refuses a reason longer than the cap', async () => {
      const { service, photos, audit } = createService();

      photos.seed(PHOTO_ID);

      await refusalOf(
        service.decide(
          reviewer,
          PHOTO_ID,
          { status: 'REJECTED', reason: 'x'.repeat(MAX_PHOTO_REJECTION_REASON_LENGTH + 1) },
          CONTEXT,
        ),
        BadRequestException,
      );

      expect(photos.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
    });
  });

  describe('decide - what is refused', () => {
    it('refuses a reviewer deciding on a photo of their own profile', async () => {
      const own: PolicySubject = { id: STAFF_ID, role: Role.OWNER };
      const { service, photos, audit, logger } = createService();

      photos.seed(PHOTO_ID, { ownerUserId: STAFF_ID });

      const refused = await refusalOf(
        service.decide(own, PHOTO_ID, { status: 'APPROVED' }, CONTEXT),
        ForbiddenException,
      );

      // A generic 403: the queue cannot be probed through it.
      expect(messageOf(refused)).toBe('Forbidden');
      expect(photos.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
      expect(logger.messages()).toEqual(['staff photo review refused: self review']);
    });

    it('refuses a photo that is no longer pending, with the generic 409', async () => {
      const { service, photos, audit } = createService();

      photos.seed(PHOTO_ID, { status: 'APPROVED', reviewedAt: EARLIER, reviewedById: STAFF_ID });

      const refused = await refusalOf(
        service.decide(reviewer, PHOTO_ID, { status: 'REJECTED' }, CONTEXT),
        ConflictException,
      );

      expect(messageOf(refused)).toBe('Conflict');
      expect(photos.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
    });

    it('answers 404 for a photo id that does not exist', async () => {
      const { service, photos, audit } = createService();

      await refusalOf(
        service.decide(reviewer, PHOTO_ID, { status: 'APPROVED' }, CONTEXT),
        NotFoundException,
      );

      expect(photos.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
    });

    it('refuses the second of two reviewers racing on one photo, and rolls back', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID);

      // The other reviewer's UPDATE landed between this request's read and write.
      jest.spyOn(photos, 'applyDecision').mockResolvedValue(0);

      await refusalOf(
        service.decide(reviewer, PHOTO_ID, { status: 'APPROVED' }, CONTEXT),
        ConflictException,
      );

      expect(row.status).toBe('PENDING');
      expect(row.reviewedAt).toBeNull();
      expect(audit.records).toEqual([]);
    });

    it('fails closed when the trail cannot be written, and undoes the decision', async () => {
      const { service, photos } = createService({ audit: new FailingAudit() });
      const row = photos.seed(PHOTO_ID);

      await refusalOf(
        service.decide(reviewer, PHOTO_ID, { status: 'APPROVED' }, CONTEXT),
        ServiceUnavailableException,
      );

      // The row is PENDING again: a decision nobody can account for was not taken.
      expect(row.status).toBe('PENDING');
      expect(row.reviewedById).toBeNull();
    });
  });

  describe('listReported', () => {
    it('lists approved reported photos, newest report first, with counts only', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { status: 'APPROVED' });
      photos.seed(SECOND_PHOTO_ID, { status: 'APPROVED' });
      photos.seed(THIRD_PHOTO_ID);
      photos.report(PHOTO_ID, EARLIER);
      photos.report(SECOND_PHOTO_ID, LATEST);
      photos.report(SECOND_PHOTO_ID, MIDDLE);
      photos.report(THIRD_PHOTO_ID, LATEST);

      const page = await service.listReported({});

      expect(page.items.map((item) => item.id)).toEqual([SECOND_PHOTO_ID, PHOTO_ID]);
      expect(page.items.map((item) => item.reportCount)).toEqual([2, 1]);
      expect(page.nextPage).toBeNull();
      expect(photos.reportedReads).toEqual([{ limit: 20, offset: 0 }]);

      // No reporter, no note and no reason: a count is the whole disclosure.
      const wire = JSON.stringify(page);

      expect(wire).not.toContain(OWNER_ID);
      expect(wire).not.toContain('note');
      expect(wire).not.toContain('reason');
    });

    it('drops a photo the moment it is taken down', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { status: 'REMOVED' });
      photos.report(PHOTO_ID, LATEST);

      await expect(service.listReported({})).resolves.toEqual({ items: [], nextPage: null });
    });

    it('pages with one extra row and names the next page', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { status: 'APPROVED' });
      photos.seed(SECOND_PHOTO_ID, { status: 'APPROVED' });
      photos.seed(THIRD_PHOTO_ID, { status: 'APPROVED' });
      photos.report(PHOTO_ID, EARLIER);
      photos.report(SECOND_PHOTO_ID, MIDDLE);
      photos.report(THIRD_PHOTO_ID, LATEST);

      const page = await service.listReported({ page: 1, limit: 2 });

      expect(page.items.map((item) => item.id)).toEqual([THIRD_PHOTO_ID, SECOND_PHOTO_ID]);
      expect(page.nextPage).toBe(2);
      expect(photos.reportedReads).toEqual([{ limit: 2, offset: 0 }]);
    });
  });

  describe('takeDown', () => {
    it('withdraws an approved photo, stamps the reviewer and writes the trail', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID, {
        status: 'APPROVED',
        reviewedAt: EARLIER,
        reviewedById: OWNER_ID,
      });

      const result = await service.takeDown(reviewer, PHOTO_ID, { reason: '  nudity  ' }, CONTEXT);

      expect(result).toEqual({ status: 'REMOVED', reviewedAt: NOW.toISOString() });
      expect(row.status).toBe('REMOVED');
      expect(row.reviewedAt).toBe(NOW);
      expect(row.reviewedById).toBe(STAFF_ID);
      expect(photos.takedowns).toHaveLength(1);
      expect(audit.records).toHaveLength(1);
      expect(audit.records[0]).toMatchObject({
        action: STAFF_PHOTO_REVIEW_AUDIT_ACTIONS.REMOVED,
        targetId: PHOTO_ID,
        metadata: {
          photoId: PHOTO_ID,
          athleteProfileId: PROFILE_ID,
          status: 'REMOVED',
          reason: 'nudity',
        },
      });
    });

    it('removes a photo that never left the queue', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID);

      await service.takeDown(reviewer, PHOTO_ID, {}, CONTEXT);

      expect(row.status).toBe('REMOVED');
      expect(audit.records[0]?.metadata).not.toHaveProperty('reason');
    });

    it('refuses a photo that is already removed with the generic 409', async () => {
      const { service, photos, audit } = createService();

      photos.seed(PHOTO_ID, { status: 'REMOVED' });

      const refused = await refusalOf(
        service.takeDown(reviewer, PHOTO_ID, {}, CONTEXT),
        ConflictException,
      );

      expect(messageOf(refused)).toBe('Conflict');
      expect(photos.takedowns).toEqual([]);
      expect(audit.records).toEqual([]);
    });

    it('refuses a reviewer taking down a photo of their own profile', async () => {
      const { service, photos, audit, logger } = createService();

      photos.seed(PHOTO_ID, { status: 'APPROVED', ownerUserId: STAFF_ID });

      const refused = await refusalOf(
        service.takeDown(reviewer, PHOTO_ID, {}, CONTEXT),
        ForbiddenException,
      );

      expect(messageOf(refused)).toBe('Forbidden');
      expect(photos.takedowns).toEqual([]);
      expect(audit.records).toEqual([]);
      expect(logger.messages()).toEqual(['staff photo review refused: self takedown']);
    });

    it('refuses the second of two takedowns racing on one photo, and rolls back', async () => {
      const { service, photos, audit } = createService();
      const row = photos.seed(PHOTO_ID, { status: 'APPROVED' });

      // The other reviewer's UPDATE landed between this request's read and write.
      jest.spyOn(photos, 'takeDown').mockResolvedValue(0);

      await refusalOf(service.takeDown(reviewer, PHOTO_ID, {}, CONTEXT), ConflictException);

      expect(row.status).toBe('APPROVED');
      expect(audit.records).toEqual([]);
    });

    it('fails closed when the trail cannot be written, and undoes the takedown', async () => {
      const { service, photos } = createService({ audit: new FailingAudit() });
      const row = photos.seed(PHOTO_ID, { status: 'APPROVED' });

      await refusalOf(
        service.takeDown(reviewer, PHOTO_ID, {}, CONTEXT),
        ServiceUnavailableException,
      );

      // The photo is APPROVED again: a takedown nobody can account for did not happen.
      expect(row.status).toBe('APPROVED');
      expect(row.reviewedById).toBeNull();
    });

    it('refuses an over-long reason before anything is written', async () => {
      const { service, photos } = createService();

      photos.seed(PHOTO_ID, { status: 'APPROVED' });

      await refusalOf(
        service.takeDown(reviewer, PHOTO_ID, { reason: 'x'.repeat(201) }, CONTEXT),
        BadRequestException,
      );

      expect(photos.takedowns).toEqual([]);
    });
  });

  describe('the guard markers the staff stack reads', () => {
    const handlers = StaffPhotoReviewController.prototype;

    it('keeps every handler on the two staff roles', () => {
      for (const name of [
        'list',
        'listReported',
        'approve',
        'reject',
        'takeDown',
        'issueViewLink',
      ] as const) {
        expect(Reflect.getMetadata(ROLES_KEY, handlers[name])).toEqual([Role.ADMIN, Role.OWNER]);
      }
    });

    it('demands a fresh second factor for decisions, takedown and view links only', () => {
      for (const name of ['approve', 'reject', 'takeDown', 'issueViewLink'] as const) {
        expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handlers[name])).toBe(true);
      }

      // Both lists are metadata reads; the staff gate is the whole requirement.
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handlers.list)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handlers.listReported)).toBeUndefined();
    });
  });
});
