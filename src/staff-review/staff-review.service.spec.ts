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
import { InMemoryAthleteProfileRepository } from '../../test/helpers/in-memory-athlete-profiles';
import { InMemoryStaffReviews } from '../../test/helpers/in-memory-staff-reviews';
import type { AuditService } from '../audit/audit.service';
import type { AthleteProfileRecord } from '../athlete/profile/athlete-profile.repository';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { PROFILE_WRONG_STATE_CODE } from '../common/errors/error-response';
import type { PrismaService } from '../database/prisma.service';
import type { ReviewResultNotification, ReviewResultNotifier } from './review-result-notifier';
import { MAX_REJECTION_REASON_LENGTH } from './staff-review.dto';
import { STAFF_REVIEW_AUDIT_ACTIONS, StaffReviewService } from './staff-review.service';

/**
 * Step B: the staff review service without HTTP.
 *
 * What is proved here is the part a suite can only see below the controller: the
 * default page, the cursor, the single conditional UPDATE, the audit row sharing
 * the decision's transaction, and an email that is allowed to fail because it
 * runs after the commit.
 */

const STAFF_ID = '11111111-1111-4111-8111-111111111111';
const PROFILE_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = 'req-review';

/** The request facts the handler passes down; the audit writer hashes the IP. */
const CONTEXT: AccessPolicyContext = { requestId: REQUEST_ID, ip: '203.0.113.7' };

/** Fixed clock: only the compared value matters, never the real time. */
const NOW = new Date('2026-07-01T09:30:00.000Z');
const EARLIER = new Date('2026-06-01T08:00:00.000Z');
const LATER = new Date('2026-06-02T08:00:00.000Z');

const reviewer: PolicySubject = { id: STAFF_ID, role: Role.ADMIN };

/** One stored profile, PENDING by default: what the queue and the detail read. */
function record(
  userId = PROFILE_ID,
  overrides: Partial<AthleteProfileRecord> = {},
): AthleteProfileRecord {
  return {
    userId,
    legalFirstName: 'Ada',
    legalLastName: 'Lovelace',
    dateOfBirth: '2016-06-15',
    gender: 'FEMALE',
    nationality: 'PK',
    countryOfResidence: 'SE',
    city: 'Karachi',
    clubName: 'KFA Academy',
    weightKg: 41,
    heightCm: 152,
    createdAt: EARLIER,
    updatedAt: EARLIER,
    reviewStatus: 'PENDING',
    submittedAt: EARLIER,
    reviewedAt: null,
    reviewedById: null,
    rejectionReason: null,
    ...overrides,
  };
}

/** The mail fake: records what was sent, and can be told to fail. */
class RecordingNotifier implements ReviewResultNotifier {
  readonly sent: ReviewResultNotification[] = [];
  failWith: Error | null = null;

  async sendResult(input: ReviewResultNotification): Promise<void> {
    if (this.failWith !== null) throw this.failWith;

    this.sent.push(input);
  }
}

/** The one thing the service needs from Prisma: an interactive transaction. */
class FakePrisma {
  readonly options: unknown[] = [];
  readonly transactions: Prisma.TransactionClient[] = [];

  constructor(private readonly profiles: InMemoryAthleteProfileRepository) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    this.options.push(options);

    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;

    this.transactions.push(tx);

    const before = new Map(this.profiles.rows);

    try {
      return await run(tx);
    } catch (error) {
      // A throw from the callback discards every write, exactly as the client does.
      this.profiles.rows.clear();
      before.forEach((row, userId) => this.profiles.rows.set(userId, row));

      throw error;
    }
  }
}

class FailingAudit extends FakeAudit {
  override async record(): Promise<void> {
    throw new Error('audit chain is unavailable');
  }
}

/** Warnings are the only thing a skipped or failed email may leave behind. */
class QuietLogger {
  readonly warns: { payload: unknown; message: string }[] = [];

  warn(payload: unknown, message = ''): void {
    this.warns.push({ payload, message });
  }

  messages(): string[] {
    return this.warns.map((entry) => entry.message);
  }
}

interface Handles {
  readonly service: StaffReviewService;
  readonly profiles: InMemoryAthleteProfileRepository;
  readonly reviews: InMemoryStaffReviews;
  readonly audit: FakeAudit;
  readonly notifier: RecordingNotifier;
  readonly logger: QuietLogger;
  readonly prisma: FakePrisma;
}

function createService(
  options: {
    audit?: FakeAudit;
    notifier?: RecordingNotifier;
    profiles?: InMemoryAthleteProfileRepository;
    reviews?: InMemoryStaffReviews;
  } = {},
): Handles {
  const profiles = options.profiles ?? new InMemoryAthleteProfileRepository();
  const reviews = options.reviews ?? new InMemoryStaffReviews();
  const audit = options.audit ?? new FakeAudit();
  const notifier = options.notifier ?? new RecordingNotifier();
  const logger = new QuietLogger();
  const prisma = new FakePrisma(profiles);

  const service = new StaffReviewService(
    prisma as unknown as PrismaService,
    profiles,
    reviews,
    notifier,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    () => NOW,
  );

  return { service, profiles, reviews, audit, notifier, logger, prisma };
}

/** Seeds rows and returns the service handles that read them. */
function serviceWith(
  rows: AthleteProfileRecord[],
  options: {
    audit?: FakeAudit;
    notifier?: RecordingNotifier;
    reviews?: InMemoryStaffReviews;
  } = {},
): Handles {
  const profiles = new InMemoryAthleteProfileRepository();

  rows.forEach((row) => profiles.rows.set(row.userId, row));

  return createService({ ...options, profiles });
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

/** The allow-listed code a refusal carries; nothing else is read out of it. */
function codeOf(error: Error): string {
  const response = (error as unknown as { getResponse: () => { code?: string } }).getResponse();

  return response.code ?? '';
}

/** The generic message a refusal carries: no field names, no submitted values. */
function messageOf(error: Error): string {
  const response = (error as unknown as { getResponse: () => { message?: string } }).getResponse();

  return response.message ?? '';
}

describe('StaffReviewService', () => {
  describe('listQueue', () => {
    it('defaults to one page of pending profiles', async () => {
      const { service, profiles } = serviceWith([record()]);
      const listForReview = jest.spyOn(profiles, 'listForReview');

      const page = await service.listQueue({});

      expect(listForReview).toHaveBeenCalledWith({ status: 'PENDING', limit: 20 });
      expect(page.items).toEqual([
        {
          profileId: PROFILE_ID,
          reviewStatus: 'PENDING',
          submittedAt: EARLIER.toISOString(),
          documentCount: 0,
        },
      ]);
      expect(page.nextCursor).toBeNull();
    });

    it('counts the active documents of the rows it returns', async () => {
      const reviews = new InMemoryStaffReviews();

      reviews.addDocument(PROFILE_ID);
      reviews.addDocument(PROFILE_ID, { kind: 'MEDAL' });
      reviews.addDocument(PROFILE_ID, { status: 'DELETED' });

      const { service } = serviceWith([record()], { reviews });
      const page = await service.listQueue({});

      // A deleted row is not evidence, so it is neither counted nor shown.
      expect(page.items[0]?.documentCount).toBe(2);
      // The grouped count runs over the page, never over the whole table.
      expect(reviews.counted).toEqual([[PROFILE_ID]]);
    });

    it('stops at the requested size and hands back the last id as the cursor', async () => {
      const first = record('44444444-4444-4444-8444-444444444444', { submittedAt: EARLIER });
      const second = record('55555555-5555-4555-8555-555555555555', { submittedAt: LATER });

      const { service } = serviceWith([first, second]);
      const page = await service.listQueue({ limit: 1 });

      expect(page.items.map((item) => item.profileId)).toEqual([first.userId]);
      expect(page.nextCursor).toBe(first.userId);
    });

    it('resumes after the cursor it is given and ends on the last page', async () => {
      const first = record('44444444-4444-4444-8444-444444444444', { submittedAt: EARLIER });
      const second = record('55555555-5555-4555-8555-555555555555', { submittedAt: LATER });

      const { service } = serviceWith([first, second]);
      const page = await service.listQueue({ limit: 1, cursor: first.userId });

      expect(page.items.map((item) => item.profileId)).toEqual([second.userId]);
      expect(page.nextCursor).toBeNull();
    });

    it('filters by the status the caller asked for, and never lists a draft', async () => {
      const approved = record(PROFILE_ID, {
        reviewStatus: 'APPROVED',
        reviewedAt: NOW,
        reviewedById: STAFF_ID,
      });
      const draft = record('66666666-6666-4666-8666-666666666666', {
        reviewStatus: 'DRAFT',
        submittedAt: null,
      });

      const { service } = serviceWith([approved, draft]);

      expect((await service.listQueue({ status: 'APPROVED' })).items).toHaveLength(1);
      expect((await service.listQueue({})).items).toHaveLength(0);
    });
  });

  describe('readDetail', () => {
    it('returns the state and the documents metadata, and nothing else', async () => {
      const reviews = new InMemoryStaffReviews();
      const document = reviews.addDocument(PROFILE_ID, { sizeBytes: 2_048 });

      const { service } = serviceWith([record()], { reviews });
      const detail = await service.readDetail(PROFILE_ID);

      // No name, no address, no object key: the reviewer gets metadata only.
      expect(Object.keys(detail).sort()).toEqual([
        'documents',
        'profileId',
        'rejectionReason',
        'reviewStatus',
        'reviewedAt',
        'submittedAt',
      ]);
      expect(detail.documents).toEqual([
        {
          id: document.id,
          kind: 'NATIONAL_ID',
          sizeBytes: 2_048,
          createdAt: document.createdAt.toISOString(),
        },
      ]);
      expect(detail.reviewStatus).toBe('PENDING');
      expect(detail.rejectionReason).toBeNull();
    });

    it('hides a document that was deleted', async () => {
      const reviews = new InMemoryStaffReviews();

      reviews.addDocument(PROFILE_ID, { status: 'DELETED' });

      const { service } = serviceWith([record()], { reviews });

      expect((await service.readDetail(PROFILE_ID)).documents).toEqual([]);
    });

    it('answers the same 404 for a profile that does not exist', async () => {
      const { service } = serviceWith([]);

      await refusalOf(service.readDetail(PROFILE_ID), NotFoundException);
    });

    it('answers that same 404 for a draft that was never submitted', async () => {
      const { service } = serviceWith([
        record(PROFILE_ID, { reviewStatus: 'DRAFT', submittedAt: null }),
      ]);

      const missing = await refusalOf(service.readDetail(PROFILE_ID), NotFoundException);

      // Nothing distinguishes "no such account" from "still filling the form".
      expect(messageOf(missing)).toBe('Not Found');
    });
  });

  describe('decide - an approval', () => {
    it('moves the row once, with the reviewer and the clock, and tells the athlete', async () => {
      const reviews = new InMemoryStaffReviews();

      reviews.recipients.set(PROFILE_ID, { email: 'ada@example.org' });

      const { service, profiles, prisma, audit, notifier, logger } = serviceWith([record()], {
        reviews,
      });
      const result = await service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT);

      expect(result).toEqual({ reviewStatus: 'APPROVED', reviewedAt: NOW.toISOString() });
      expect(profiles.decisions).toEqual([
        {
          userId: PROFILE_ID,
          decision: {
            status: 'APPROVED',
            reviewedAt: NOW,
            reviewedById: STAFF_ID,
            rejectionReason: null,
          },
        },
      ]);
      // Bounded, so a held lock fails the request instead of hanging it.
      expect(prisma.options).toEqual([{ maxWait: 5_000, timeout: 10_000 }]);
      expect(notifier.sent).toEqual([{ to: 'ada@example.org', status: 'APPROVED', reason: null }]);
      expect(logger.messages()).toEqual([]);
    });

    it('writes the trail row joined to the decision transaction', async () => {
      const { service, prisma, audit } = serviceWith([record()]);

      await service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT);

      expect(audit.records).toEqual([
        {
          action: STAFF_REVIEW_AUDIT_ACTIONS.APPROVED,
          actorId: STAFF_ID,
          actorRole: String(Role.ADMIN),
          targetType: 'athlete_profile',
          targetId: PROFILE_ID,
          requestId: REQUEST_ID,
          ip: CONTEXT.ip,
          // An approval has no words to keep, and no profile data is copied here.
          metadata: {},
        },
      ]);
      expect(audit.transactions[0]).toBe(prisma.transactions[0]);
    });

    it('keeps the decision when the transport fails, and warns without the address', async () => {
      const reviews = new InMemoryStaffReviews();
      const notifier = new RecordingNotifier();

      reviews.recipients.set(PROFILE_ID, { email: 'ada@example.org' });
      notifier.failWith = new Error('smtp is down');

      const { service, profiles, logger } = serviceWith([record()], { reviews, notifier });
      const result = await service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT);

      expect(result.reviewStatus).toBe('APPROVED');
      expect(profiles.rows.get(PROFILE_ID)?.reviewStatus).toBe('APPROVED');
      expect(logger.messages()).toEqual(['review decision email failed']);
      // The warning names the request and the outcome, never the athlete.
      expect(logger.warns[0]?.payload).toEqual({
        requestId: REQUEST_ID,
        profileId: PROFILE_ID,
        status: 'APPROVED',
      });
    });

    it('skips the email and warns when the profile has no address', async () => {
      const { service, notifier, logger } = serviceWith([record()]);

      await service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT);

      expect(notifier.sent).toEqual([]);
      expect(logger.messages()).toEqual(['review decision email skipped: no address on file']);
    });

    it('skips the email and warns when the address cannot be read', async () => {
      const reviews = new InMemoryStaffReviews();

      reviews.failRecipientWith = new Error('the accounts table is unavailable');

      const { service, notifier, logger } = serviceWith([record()], { reviews });

      await service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT);

      expect(notifier.sent).toEqual([]);
      expect(logger.messages()).toEqual(['review decision email skipped: recipient unreadable']);
    });
  });

  describe('decide - a rejection', () => {
    it('keeps the trimmed words in the row, the trail and the email', async () => {
      const reviews = new InMemoryStaffReviews();

      reviews.recipients.set(PROFILE_ID, { email: 'ada@example.org' });

      const { service, profiles, audit, notifier } = serviceWith([record()], { reviews });

      await service.decide(
        reviewer,
        PROFILE_ID,
        { status: 'REJECTED', reason: '  the passport photo is blurry  ' },
        CONTEXT,
      );

      expect(profiles.rows.get(PROFILE_ID)).toMatchObject({
        reviewStatus: 'REJECTED',
        rejectionReason: 'the passport photo is blurry',
        reviewedById: STAFF_ID,
        reviewedAt: NOW,
      });
      expect(audit.records[0]?.action).toBe(STAFF_REVIEW_AUDIT_ACTIONS.REJECTED);
      expect(audit.records[0]?.metadata).toEqual({ reason: 'the passport photo is blurry' });
      expect(notifier.sent).toEqual([
        { to: 'ada@example.org', status: 'REJECTED', reason: 'the passport photo is blurry' },
      ]);
    });

    it('refuses a rejection with no reason, before anything is written', async () => {
      const { service, profiles, audit, notifier } = serviceWith([record()]);

      const refused = await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'REJECTED', reason: '   ' }, CONTEXT),
        BadRequestException,
      );

      expect(messageOf(refused)).toBe('Bad Request');
      expect(profiles.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
      expect(notifier.sent).toEqual([]);
    });

    it('refuses a reason longer than the column, and one that is not text', async () => {
      const { service, profiles } = serviceWith([record()]);
      const tooLong = 'x'.repeat(MAX_REJECTION_REASON_LENGTH + 1);

      await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'REJECTED', reason: tooLong }, CONTEXT),
        BadRequestException,
      );
      await refusalOf(
        service.decide(
          reviewer,
          PROFILE_ID,
          { status: 'REJECTED', reason: 42 as unknown as string },
          CONTEXT,
        ),
        BadRequestException,
      );

      expect(profiles.decisions).toEqual([]);
    });

    it('ignores a reason on an approval', async () => {
      const { service, profiles, audit } = serviceWith([record()]);

      await service.decide(
        reviewer,
        PROFILE_ID,
        { status: 'APPROVED', reason: '  not a reason  ' },
        CONTEXT,
      );

      expect(profiles.rows.get(PROFILE_ID)?.rejectionReason).toBeNull();
      expect(audit.records[0]?.metadata).toEqual({});
    });
  });

  describe('decide - what is refused', () => {
    it('refuses a reviewer deciding on their own profile', async () => {
      const own: PolicySubject = { id: PROFILE_ID, role: Role.ADMIN };
      const { service, profiles, audit, notifier, logger } = serviceWith([record()]);

      const refused = await refusalOf(
        service.decide(own, PROFILE_ID, { status: 'APPROVED' }, CONTEXT),
        ForbiddenException,
      );

      // A generic 403: the queue cannot be probed through it.
      expect(messageOf(refused)).toBe('Forbidden');
      expect(profiles.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
      expect(notifier.sent).toEqual([]);
      expect(logger.messages()).toEqual(['staff review refused: self review']);
    });

    it('refuses a profile that is no longer pending, with the allow-listed code', async () => {
      const approved = record(PROFILE_ID, {
        reviewStatus: 'APPROVED',
        reviewedAt: NOW,
        reviewedById: STAFF_ID,
      });
      const { service, profiles, audit } = serviceWith([approved]);

      const refused = await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'REJECTED', reason: 'too late' }, CONTEXT),
        ConflictException,
      );

      expect(codeOf(refused)).toBe(PROFILE_WRONG_STATE_CODE);
      expect(profiles.decisions).toEqual([]);
      expect(audit.records).toEqual([]);
    });

    it('answers 404 for a profile that was never submitted', async () => {
      const { service, profiles } = serviceWith([
        record(PROFILE_ID, { reviewStatus: 'DRAFT', submittedAt: null }),
      ]);

      await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT),
        NotFoundException,
      );

      expect(profiles.decisions).toEqual([]);
    });

    it('refuses the second of two reviewers racing on one profile, and rolls back', async () => {
      const { service, profiles, audit, notifier } = serviceWith([record()]);

      // The other reviewer's UPDATE landed between this request's read and write.
      jest.spyOn(profiles, 'applyReviewDecision').mockResolvedValue(0);

      const refused = await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT),
        ConflictException,
      );

      expect(codeOf(refused)).toBe(PROFILE_WRONG_STATE_CODE);
      expect(profiles.rows.get(PROFILE_ID)?.reviewStatus).toBe('PENDING');
      expect(audit.records).toEqual([]);
      expect(notifier.sent).toEqual([]);
    });

    it('fails closed when the trail cannot be written, and undoes the decision', async () => {
      const { service, profiles, notifier } = serviceWith([record()], {
        audit: new FailingAudit(),
      });

      await refusalOf(
        service.decide(reviewer, PROFILE_ID, { status: 'APPROVED' }, CONTEXT),
        ServiceUnavailableException,
      );

      // The row is PENDING again: a decision nobody can account for was not taken.
      expect(profiles.rows.get(PROFILE_ID)?.reviewStatus).toBe('PENDING');
      expect(notifier.sent).toEqual([]);
    });
  });
});
