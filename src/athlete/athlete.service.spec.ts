import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { ResourceOwnershipService } from '../auth/policy/resource-ownership.service';
import { Role } from '../auth/roles';
import type { PrismaService } from '../database/prisma.service';
import { SubscriptionStatusService } from '../billing/subscription-status.service';
import { ATHLETE_AUDIT_ACTIONS, AthleteService, subscriptionRequiredFor } from './athlete.service';
import type {
  AthleteProfileInput,
  AthleteProfileRecord,
  AthleteProfileRepository,
} from './profile/athlete-profile.repository';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '22222222-2222-4222-8222-222222222222';
const REQUEST_ID = 'req-athlete';

/** The request facts a handler passes down; the service hashes the IP. */
const CONTEXT: AccessPolicyContext = { requestId: REQUEST_ID, ip: '203.0.113.7' };

/** Fixed clock: the profile rules never read the real time in this suite. */
const NOW = new Date('2026-06-15T12:00:00.000Z');

const actor: PolicySubject = { id: USER_ID, role: Role.ATHLETE };

const INPUT: AthleteProfileInput = {
  legalFirstName: 'Ada',
  legalLastName: 'Lovelace',
  dateOfBirth: '2000-06-15',
  gender: 'FEMALE',
  nationality: 'PK',
  countryOfResidence: 'SE',
  city: 'Karachi',
  clubName: 'KFA Academy',
  weightKg: 61,
  heightCm: 168,
};

function record(
  userId = USER_ID,
  overrides: Partial<AthleteProfileInput> = {},
): AthleteProfileRecord {
  const merged: AthleteProfileInput = { ...INPUT, ...overrides };

  return {
    userId,
    legalFirstName: merged.legalFirstName,
    legalLastName: merged.legalLastName,
    dateOfBirth: merged.dateOfBirth,
    gender: merged.gender,
    nationality: merged.nationality,
    countryOfResidence: merged.countryOfResidence,
    city: merged.city,
    clubName: merged.clubName ?? null,
    weightKg: merged.weightKg ?? null,
    heightCm: merged.heightCm ?? null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    reviewStatus: 'DRAFT',
    submittedAt: null,
    reviewedAt: null,
    reviewedById: null,
    rejectionReason: null,
  };
}

/** Records the calls, so a refused request can be proven not to write. */
class RecordingProfiles implements AthleteProfileRepository {
  readonly rows = new Map<string, AthleteProfileRecord>();
  readonly upserts: string[] = [];
  /** The client each write went through; `undefined` when the call had none. */
  readonly transactions: (Prisma.TransactionClient | undefined)[] = [];

  async findByUserId(userId: string): Promise<AthleteProfileRecord | null> {
    return this.rows.get(userId) ?? null;
  }

  async upsertForUser(
    userId: string,
    data: AthleteProfileInput,
    tx?: Prisma.TransactionClient,
  ): Promise<AthleteProfileRecord> {
    this.upserts.push(userId);
    this.transactions.push(tx);

    const previous = this.rows.get(userId);
    const next: AthleteProfileRecord = {
      userId,
      ...data,
      clubName: data.clubName ?? null,
      weightKg: data.weightKg ?? null,
      heightCm: data.heightCm ?? null,
      createdAt: previous?.createdAt ?? NOW,
      updatedAt: NOW,
      reviewStatus: previous?.reviewStatus ?? 'DRAFT',
      submittedAt: previous?.submittedAt ?? null,
      reviewedAt: previous?.reviewedAt ?? null,
      reviewedById: previous?.reviewedById ?? null,
      rejectionReason: previous?.rejectionReason ?? null,
    };

    this.rows.set(userId, next);

    return next;
  }

  /** Set to make the conditional update lose, as a concurrent submit would. */
  steal = false;
  readonly submissions: string[] = [];

  async submitForReview(
    userId: string,
    submittedAt: Date,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    this.submissions.push(userId);
    this.transactions.push(tx);

    const current = this.rows.get(userId);

    // The same guard the conditional updateMany applies in one statement.
    if (
      this.steal ||
      current === undefined ||
      !['DRAFT', 'REJECTED'].includes(current.reviewStatus)
    ) {
      return 0;
    }

    this.rows.set(userId, {
      ...current,
      reviewStatus: 'PENDING',
      submittedAt,
      rejectionReason: null,
    });

    return 1;
  }

  /** The review surface is not the athlete surface: a call here is a wiring bug. */
  async listForReview(): Promise<AthleteProfileRecord[]> {
    throw new Error('the athlete service never lists the review queue');
  }

  async applyReviewDecision(): Promise<number> {
    throw new Error('the athlete service never decides a review');
  }

  /** The commits a rollback has to undo. */
  snapshot(): Map<string, AthleteProfileRecord> {
    return new Map(this.rows);
  }

  restore(snapshot: Map<string, AthleteProfileRecord>): void {
    this.rows.clear();
    snapshot.forEach((row, userId) => this.rows.set(userId, row));
  }
}

/**
 * The one thing the service needs from Prisma: an interactive transaction. A
 * throw from the callback discards everything the callback wrote, exactly as the
 * real client does, so a fail-closed path can be checked for a real rollback.
 */
class FakePrisma {
  readonly transactions: Prisma.TransactionClient[] = [];

  /** How many active identity documents the submit precondition will count. */
  activeDocuments = 0;

  readonly identityDocument = {
    count: (): Promise<number> => Promise.resolve(this.activeDocuments),
  };

  constructor(private readonly profiles: RecordingProfiles) {}

  async $transaction<T>(run: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    // A plain marker: both fakes ignore the client and only have to agree on it.
    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;

    this.transactions.push(tx);

    const before = this.profiles.snapshot();

    try {
      return await run(tx);
    } catch (error) {
      this.profiles.restore(before);

      throw error;
    }
  }
}

class FailingAudit extends FakeAudit {
  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    await super.record(entry, tx);

    throw new Error('audit chain is unavailable');
  }
}

class QuietLogger {
  readonly warns: unknown[] = [];

  warn(payload: unknown): void {
    this.warns.push(payload);
  }
}

function createService(
  audit: FakeAudit = new FakeAudit(),
  profiles = new RecordingProfiles(),
  paid = true,
) {
  const logger = new QuietLogger();
  const prisma = new FakePrisma(profiles);
  const ownership = new ResourceOwnershipService(
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );
  const service = new AthleteService(
    prisma as unknown as PrismaService,
    profiles,
    ownership,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    () => NOW,
    // Paid unless a test says otherwise; the unpaid gate has its own test.
    {
      isActive: async () => paid,
      statusOf: async () => (paid ? 'ACTIVE' : 'NONE'),
      statusesOf: async () => new Map(),
    } as unknown as SubscriptionStatusService,
  );

  return { service, audit, profiles, logger, prisma };
}

function successRecords(audit: FakeAudit): AuditRecord[] {
  return audit.records.filter((row) => row.action.startsWith('athlete.profile.'));
}

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
async function codeOf(call: Promise<unknown>): Promise<string> {
  const error = await refusalOf(call, ConflictException);

  return (error as unknown as { getResponse: () => { code?: string } }).getResponse().code ?? '';
}

describe('AthleteService', () => {
  it('creates on the first save and audits the field names only', async () => {
    const { service, audit, profiles } = createService();

    const view = await service.saveProfile(actor, INPUT, CONTEXT);

    expect(profiles.upserts).toEqual([USER_ID]);
    expect(view).toMatchObject({ city: 'Karachi', isMinor: false });

    const [entry] = successRecords(audit);

    expect(entry).toMatchObject({
      action: ATHLETE_AUDIT_ACTIONS.PROFILE_CREATE,
      actorId: USER_ID,
      actorRole: Role.ATHLETE,
      targetType: 'athlete_profile',
      targetId: USER_ID,
      requestId: REQUEST_ID,
    });
    expect(entry?.metadata).toEqual({
      fields: [
        'legalFirstName',
        'legalLastName',
        'dateOfBirth',
        'gender',
        'nationality',
        'countryOfResidence',
        'city',
        'clubName',
        'weightKg',
        'heightCm',
      ],
    });

    const trail = JSON.stringify(audit.records);

    expect(trail).not.toContain('Karachi');
    expect(trail).not.toContain('2000-06-15');
    expect(trail).not.toContain('KFA Academy');
  });

  it('audits the names of the fields that actually changed', async () => {
    const { service, audit, profiles } = createService();

    profiles.rows.set(USER_ID, record(USER_ID, { city: 'Karachi', weightKg: 61 }));

    await service.saveProfile(actor, { ...INPUT, city: 'Lahore', weightKg: null }, CONTEXT);

    expect(successRecords(audit).map((row) => row.metadata)).toEqual([
      { fields: ['city', 'weightKg'] },
    ]);
  });

  it('records no change when the same body is saved twice', async () => {
    const { service, audit, profiles } = createService();

    profiles.rows.set(USER_ID, record());

    await service.saveProfile(actor, INPUT, CONTEXT);

    expect(successRecords(audit).map((row) => row.metadata)).toEqual([{ fields: [] }]);
  });

  it('fails closed when the trail cannot be written', async () => {
    const { service, profiles } = createService(new FailingAudit());

    await refusalOf(service.saveProfile(actor, INPUT, CONTEXT), ServiceUnavailableException);

    // The upsert ran first, but the failed trail rolls the row back with it.
    expect(profiles.upserts).toEqual([USER_ID]);
    expect(profiles.rows.size).toBe(0);
  });

  it('writes the row and the trail through the same transaction', async () => {
    const audit = new FakeAudit();
    const { service, profiles, prisma } = createService(audit);

    await service.saveProfile(actor, INPUT, CONTEXT);

    const [tx] = prisma.transactions;

    expect(prisma.transactions).toHaveLength(1);
    expect(tx).toBeDefined();
    // One unit of work: the row and its audit row commit together or not at all.
    expect(profiles.transactions).toEqual([tx]);
    expect(audit.transactions).toEqual([tx]);
    expect(profiles.rows.has(USER_ID)).toBe(true);
  });

  it('derives isMinor from the injected clock', async () => {
    const { service, profiles } = createService();

    profiles.rows.set(USER_ID, record(USER_ID, { dateOfBirth: '2008-06-15' }));
    await expect(service.readProfile(actor, CONTEXT)).resolves.toMatchObject({ isMinor: false });

    profiles.rows.set(USER_ID, record(USER_ID, { dateOfBirth: '2008-06-16' }));
    await expect(service.readProfile(actor, CONTEXT)).resolves.toMatchObject({ isMinor: true });
  });

  it('refuses a stored profile that belongs to somebody else', async () => {
    const { service, audit, profiles } = createService();

    // A repository returning a foreign row is a bug; the ownership check answers.
    profiles.rows.set(USER_ID, record(OTHER_ID));

    await refusalOf(service.readProfile(actor, CONTEXT), ForbiddenException);
    await refusalOf(service.saveProfile(actor, INPUT, CONTEXT), ForbiddenException);

    expect(profiles.upserts).toEqual([]);
    expect(successRecords(audit)).toEqual([]);
    expect(audit.records.map((row) => row.action)).toEqual(['authz.denied', 'authz.denied']);
  });

  it('reports a missing profile as not found', async () => {
    const { service } = createService();

    await refusalOf(service.readProfile(actor, CONTEXT), NotFoundException);
  });

  it('returns the profile fields plus isMinor and updatedAt', async () => {
    const { service, profiles } = createService();

    profiles.rows.set(USER_ID, record());

    const view = await service.readProfile(actor, CONTEXT);

    expect(Object.keys(view).sort()).toEqual([
      'city',
      'clubName',
      'countryOfResidence',
      'dateOfBirth',
      'gender',
      'heightCm',
      'isMinor',
      'legalFirstName',
      'legalLastName',
      'nationality',
      'reviewStatus',
      'submittedAt',
      'subscriptionRequired',
      'updatedAt',
      'weightKg',
    ]);
    expect(view.updatedAt).toBe('2026-01-02T00:00:00.000Z');
    expect(JSON.stringify(view)).not.toContain(USER_ID);
  });

  it('marks only an unpaid pending resume subscriptionRequired', async () => {
    const { service, profiles } = createService(undefined, undefined, false);

    profiles.rows.set(USER_ID, { ...record(), reviewStatus: 'PENDING', submittedAt: NOW });

    await expect(service.readProfile(actor, CONTEXT)).resolves.toMatchObject({
      subscriptionRequired: true,
    });

    expect(subscriptionRequiredFor('PENDING', false)).toBe(true);
    expect(subscriptionRequiredFor('PENDING', true)).toBe(false);
    expect(subscriptionRequiredFor('APPROVED', false)).toBe(false);
  });

  it('submits a draft profile and answers pending with the timestamp', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, record());
    prisma.activeDocuments = 1;

    const result = await service.submitForReview(actor, INPUT, CONTEXT);
    const stored = profiles.rows.get(USER_ID);

    expect(result).toEqual({ reviewStatus: 'PENDING', submittedAt: expect.any(String) });
    expect(stored?.reviewStatus).toBe('PENDING');
    expect(stored?.submittedAt).toBeInstanceOf(Date);
    expect(stored?.rejectionReason).toBeNull();

    // The row and its trail share one unit of work.
    const submissions = audit.records.filter(
      (row) => row.action === ATHLETE_AUDIT_ACTIONS.PROFILE_SUBMITTED,
    );

    expect(submissions).toHaveLength(1);
    expect(profiles.transactions).toEqual([prisma.transactions[0]]);
    expect(audit.transactions).toEqual([prisma.transactions[0]]);
  });

  it('resubmits a rejected profile and opens the edit again', async () => {
    const { service, profiles, prisma } = createService();
    const rejectedAt = new Date('2026-05-01T00:00:00.000Z');

    profiles.rows.set(USER_ID, {
      ...record(),
      reviewStatus: 'REJECTED',
      submittedAt: rejectedAt,
      reviewedAt: rejectedAt,
      reviewedById: OTHER_ID,
      rejectionReason: 'photo unreadable',
    });
    prisma.activeDocuments = 1;

    await service.submitForReview(actor, INPUT, CONTEXT);

    const stored = profiles.rows.get(USER_ID);

    expect(stored?.reviewStatus).toBe('PENDING');
    expect(stored?.rejectionReason).toBeNull();
    expect(stored?.submittedAt).not.toEqual(rejectedAt);
  });

  it('refuses a second submit while one is already pending', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, { ...record(), reviewStatus: 'PENDING', submittedAt: NOW });
    prisma.activeDocuments = 1;

    await expect(codeOf(service.submitForReview(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_wrong_state',
    );

    // The refusal happens before the conditional update, so nothing is attempted.
    expect(profiles.submissions).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('refuses to submit a profile that is already approved', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, { ...record(), reviewStatus: 'APPROVED', submittedAt: NOW });
    prisma.activeDocuments = 1;

    await expect(codeOf(service.submitForReview(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_wrong_state',
    );
    expect(profiles.submissions).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('refuses to submit an account without a profile', async () => {
    const { service, audit, prisma } = createService();

    prisma.activeDocuments = 1;

    await expect(codeOf(service.submitForReview(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_not_ready',
    );
    expect(audit.records).toEqual([]);
  });

  it('refuses to submit without an active identity document', async () => {
    const { service, audit, profiles } = createService();

    profiles.rows.set(USER_ID, record());

    await expect(codeOf(service.submitForReview(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_not_ready',
    );

    // The profile is untouched and nothing is attempted.
    expect(profiles.rows.get(USER_ID)?.reviewStatus).toBe('DRAFT');
    expect(profiles.submissions).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('refuses to submit a profile that fails its own rules', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, record());
    prisma.activeDocuments = 1;

    await expect(
      codeOf(service.submitForReview(actor, { ...INPUT, city: '' }, CONTEXT)),
    ).resolves.toBe('profile_not_ready');
    expect(profiles.submissions).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('loses the submit to a concurrent writer without a second trail row', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, record());
    profiles.steal = true;
    prisma.activeDocuments = 1;

    // The read saw DRAFT while the conditional update matched no row: a conflict,
    // never a second transition of an already submitted profile.
    await expect(codeOf(service.submitForReview(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_wrong_state',
    );

    expect(profiles.submissions).toEqual([USER_ID]);
    expect(profiles.rows.get(USER_ID)?.reviewStatus).toBe('DRAFT');
    expect(audit.records).toEqual([]);
  });

  it('audits the submit by name only, with no profile values', async () => {
    const { service, audit, profiles, prisma } = createService();

    profiles.rows.set(USER_ID, record());
    prisma.activeDocuments = 1;

    await service.submitForReview(actor, INPUT, CONTEXT);

    const [entry] = audit.records;

    expect(entry).toMatchObject({
      action: ATHLETE_AUDIT_ACTIONS.PROFILE_SUBMITTED,
      actorId: USER_ID,
      actorRole: Role.ATHLETE,
      targetType: 'athlete_profile',
      targetId: USER_ID,
      requestId: REQUEST_ID,
      metadata: { fields: [] },
    });

    const trail = JSON.stringify(entry);

    expect(trail).not.toContain('Ada');
    expect(trail).not.toContain('Lovelace');
    expect(trail).not.toContain('Karachi');
  });

  it('locks edits while the profile is pending', async () => {
    const { service, audit, profiles } = createService();

    profiles.rows.set(USER_ID, { ...record(), reviewStatus: 'PENDING', submittedAt: NOW });

    await expect(codeOf(service.saveProfile(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_edit_locked',
    );

    // A locked edit writes neither the row nor a trail row.
    expect(profiles.upserts).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('locks edits while the profile is approved', async () => {
    const { service, audit, profiles } = createService();

    profiles.rows.set(USER_ID, { ...record(), reviewStatus: 'APPROVED', submittedAt: NOW });

    await expect(codeOf(service.saveProfile(actor, INPUT, CONTEXT))).resolves.toBe(
      'profile_edit_locked',
    );
    expect(profiles.upserts).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('keeps edits open while the profile is draft or rejected', async () => {
    const { service, profiles } = createService();

    profiles.rows.set(USER_ID, record());
    await expect(service.saveProfile(actor, INPUT, CONTEXT)).resolves.toMatchObject({
      reviewStatus: 'DRAFT',
    });

    profiles.rows.set(USER_ID, {
      ...record(),
      reviewStatus: 'REJECTED',
      rejectionReason: 'photo unreadable',
    });
    await expect(service.saveProfile(actor, INPUT, CONTEXT)).resolves.toMatchObject({
      reviewStatus: 'REJECTED',
    });

    expect(profiles.upserts).toEqual([USER_ID, USER_ID]);
  });

  it('shows the rejection reason only for a rejected profile', async () => {
    const { service, profiles } = createService();

    profiles.rows.set(USER_ID, record());
    await expect(service.readProfile(actor, CONTEXT)).resolves.not.toHaveProperty(
      'rejectionReason',
    );

    profiles.rows.set(USER_ID, {
      ...record(),
      reviewStatus: 'PENDING',
      submittedAt: NOW,
      rejectionReason: 'photo unreadable',
    });

    const pending = await service.readProfile(actor, CONTEXT);

    // A stale reason on a pending row is not shown, and the timestamp is.
    expect(pending).not.toHaveProperty('rejectionReason');
    expect(pending.submittedAt).toBe(NOW.toISOString());

    profiles.rows.set(USER_ID, {
      ...record(),
      reviewStatus: 'REJECTED',
      rejectionReason: 'photo unreadable',
    });

    await expect(service.readProfile(actor, CONTEXT)).resolves.toMatchObject({
      reviewStatus: 'REJECTED',
      rejectionReason: 'photo unreadable',
    });
  });
});
