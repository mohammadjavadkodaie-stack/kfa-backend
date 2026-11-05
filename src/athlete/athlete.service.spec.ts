import { ForbiddenException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { ResourceOwnershipService } from '../auth/policy/resource-ownership.service';
import { Role } from '../auth/roles';
import type { PrismaService } from '../database/prisma.service';
import { ATHLETE_AUDIT_ACTIONS, AthleteService } from './athlete.service';
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
    };

    this.rows.set(userId, next);

    return next;
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

function createService(audit: FakeAudit = new FakeAudit(), profiles = new RecordingProfiles()) {
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
      'updatedAt',
      'weightKg',
    ]);
    expect(view.updatedAt).toBe('2026-01-02T00:00:00.000Z');
    expect(JSON.stringify(view)).not.toContain(USER_ID);
  });
});
