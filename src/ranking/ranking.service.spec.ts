import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PATH_METADATA } from '@nestjs/common/constants';
import type { Prisma, ReviewStatus } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import { AUTHENTICATED_KEY } from '../auth/decorators/authenticated.decorator';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import type { PrismaService } from '../database/prisma.service';
import {
  createCompetitionResultSchema,
  parseCreateCompetitionResult,
  parseUpdateCompetitionResult,
  updateCompetitionResultSchema,
} from './ranking.dto';
import type {
  CompetitionResultPatch,
  CompetitionResultRow,
  CompetitionResultTarget,
  NewCompetitionResult,
  RankingProfile,
  RankingRepository,
  RankingRow,
  RankingTotal,
} from './ranking.repository';
import { assignCompetitionRanks, RANKING_AUDIT_ACTIONS, RankingService } from './ranking.service';
import { StaffRankingController } from './staff-ranking.controller';

/**
 * Stage 8a without HTTP or PostgreSQL.
 *
 * What is proved here: no athlete or user can reach a write route, the two
 * ranking writes are the only place a score comes from, the tie rule, the
 * recompute after create/update/delete, one audit row per changed athlete, the
 * advisory lock before the reads, fail-closed rollback, the self-profile
 * refusal, the generic 404 for a non-approved resume, and the strict DTOs.
 */

const STAFF_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_STAFF_ID = '22222222-2222-4222-8222-222222222222';
const ATHLETE_USER_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_USER_ID = '44444444-4444-4444-8444-444444444444';
const PROFILE_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROFILE_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const REQUEST_ID = 'req-ranking';
const CONTEXT: AccessPolicyContext = { requestId: REQUEST_ID, ip: '203.0.113.9' };

const reviewer: PolicySubject = { id: STAFF_ID, role: Role.ADMIN };

/** One stored profile: only what the entry check reads. */
type StoredProfile = RankingProfile;

/** Snapshot of the two mutable tables, enough for a real rollback. */
interface RankingSnapshot {
  readonly results: Map<string, CompetitionResultRow>;
  readonly rankings: Map<string, RankingRow>;
}

/**
 * The `competition_results` and `athlete_rankings` tables without PostgreSQL.
 * The ORDER of the calls is recorded, which is how the lock-before-recompute
 * rule is checked.
 */
class InMemoryRankingRepository implements RankingRepository {
  readonly profiles = new Map<string, StoredProfile>();
  readonly results = new Map<string, CompetitionResultRow>();
  readonly rankings = new Map<string, RankingRow>();
  readonly events: string[] = [];

  private sequence = 0;
  private dateSequence = 0;

  seedProfile(id: string, userId: string, reviewStatus: ReviewStatus = 'APPROVED'): StoredProfile {
    const profile: StoredProfile = { id, userId, reviewStatus };

    this.profiles.set(id, profile);

    return profile;
  }

  seedResult(input: {
    readonly id?: string;
    readonly athleteProfileId: string;
    readonly points: number;
    readonly eventName?: string;
    readonly eventDate?: string;
  }): CompetitionResultRow {
    const id = input.id ?? `result-${(this.sequence += 1)}`;
    const createdAt = this.nextDate();
    const row: CompetitionResultRow = {
      id,
      athleteProfileId: input.athleteProfileId,
      eventName: input.eventName ?? 'National Championship',
      eventDate: new Date(`${input.eventDate ?? '2026-05-01'}T00:00:00.000Z`),
      points: input.points,
      enteredById: OTHER_STAFF_ID,
      createdAt,
      updatedAt: createdAt,
    };

    this.results.set(id, row);

    return row;
  }

  seedRanking(athleteProfileId: string, totalPoints: number, rank: number): RankingRow {
    const row: RankingRow = { athleteProfileId, totalPoints, rank };

    this.rankings.set(athleteProfileId, row);

    return row;
  }

  async findProfile(athleteProfileId: string): Promise<RankingProfile | null> {
    return this.profiles.get(athleteProfileId) ?? null;
  }

  async findResult(resultId: string): Promise<CompetitionResultTarget | null> {
    const row = this.results.get(resultId);
    const profile = row === undefined ? undefined : this.profiles.get(row.athleteProfileId);

    if (row === undefined || profile === undefined) return null;

    return { ...row, ownerUserId: profile.userId, reviewStatus: profile.reviewStatus };
  }

  async createResult(input: NewCompetitionResult, _tx: Prisma.TransactionClient) {
    const at = this.nextDate();
    const row: CompetitionResultRow = {
      id: `result-${(this.sequence += 1)}`,
      athleteProfileId: input.athleteProfileId,
      eventName: input.eventName,
      eventDate: input.eventDate,
      points: input.points,
      enteredById: input.enteredById,
      createdAt: at,
      updatedAt: at,
    };

    this.results.set(row.id, row);
    this.events.push('create');

    return row;
  }

  async updateResult(
    resultId: string,
    patch: CompetitionResultPatch,
    _tx: Prisma.TransactionClient,
  ): Promise<number> {
    const row = this.results.get(resultId);

    if (row === undefined) return 0;

    this.results.set(resultId, { ...row, ...patch, updatedAt: this.nextDate() });
    this.events.push('update');

    return 1;
  }

  async deleteResult(resultId: string, _tx: Prisma.TransactionClient): Promise<number> {
    this.events.push('delete');

    return this.results.delete(resultId) ? 1 : 0;
  }

  async listResults(
    athleteProfileId: string | undefined,
    limit: number,
    cursor: string | undefined,
  ): Promise<CompetitionResultRow[]> {
    const rows = [...this.results.values()]
      .filter((row) => athleteProfileId === undefined || row.athleteProfileId === athleteProfileId)
      .sort(
        (left, right) =>
          right.eventDate.getTime() - left.eventDate.getTime() ||
          right.createdAt.getTime() - left.createdAt.getTime() ||
          right.id.localeCompare(left.id),
      );
    const start = cursor === undefined ? 0 : rows.findIndex((row) => row.id === cursor) + 1;

    return rows.slice(Math.max(0, start), Math.max(0, start) + limit + 1);
  }

  async lock(_tx: Prisma.TransactionClient): Promise<void> {
    this.events.push('lock');
  }

  async sumApprovedTotals(_tx: Prisma.TransactionClient): Promise<RankingTotal[]> {
    this.events.push('totals');

    const totals = new Map<string, number>();

    for (const row of this.results.values()) {
      if (this.profiles.get(row.athleteProfileId)?.reviewStatus !== 'APPROVED') continue;

      totals.set(row.athleteProfileId, (totals.get(row.athleteProfileId) ?? 0) + row.points);
    }

    return [...totals].map(([athleteProfileId, totalPoints]) => ({
      athleteProfileId,
      totalPoints,
    }));
  }

  async listRankings(_tx: Prisma.TransactionClient): Promise<RankingRow[]> {
    this.events.push('rankings');

    return [...this.rankings.values()].map((row) => ({ ...row }));
  }

  async upsertRanking(row: RankingRow, _tx: Prisma.TransactionClient): Promise<void> {
    this.events.push('upsert');
    this.rankings.set(row.athleteProfileId, { ...row });
  }

  async deleteRanking(athleteProfileId: string, _tx: Prisma.TransactionClient): Promise<void> {
    this.events.push('delete-ranking');
    this.rankings.delete(athleteProfileId);
  }

  snapshot(): RankingSnapshot {
    return {
      results: new Map([...this.results].map(([id, row]) => [id, { ...row }])),
      rankings: new Map([...this.rankings].map(([id, row]) => [id, { ...row }])),
    };
  }

  restore(snapshot: RankingSnapshot): void {
    this.results.clear();
    this.rankings.clear();
    snapshot.results.forEach((row, id) => this.results.set(id, { ...row }));
    snapshot.rankings.forEach((row, id) => this.rankings.set(id, { ...row }));
  }

  private nextDate(): Date {
    return new Date(Date.parse('2026-09-01T00:00:00.000Z') + (this.dateSequence += 1_000));
  }
}

/** The one thing the service needs from Prisma: an interactive transaction. */
class FakePrisma {
  readonly options: unknown[] = [];
  readonly transactions: Prisma.TransactionClient[] = [];

  constructor(private readonly repository: InMemoryRankingRepository) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    this.options.push(options);

    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;
    const before = this.repository.snapshot();

    this.transactions.push(tx);

    try {
      return await run(tx);
    } catch (error) {
      // A throw from the callback discards every write, exactly as the real
      // client does, so a fail-closed path is a real rollback here.
      this.repository.restore(before);

      throw error;
    }
  }
}

/** An audit chain that goes down after `succeedFirst` rows were written. */
class FailingAudit extends FakeAudit {
  constructor(private readonly succeedFirst = 0) {
    super();
  }

  override async record(entry: Parameters<FakeAudit['record']>[0], tx?: unknown): Promise<void> {
    if (this.records.length < this.succeedFirst) return super.record(entry, tx);

    throw new Error('audit chain is unavailable');
  }
}

/** Warnings are the only thing a refused or failed trail may leave behind. */
class QuietLogger {
  readonly warns: { payload: unknown; message: string }[] = [];

  warn(payload: unknown, message = ''): void {
    this.warns.push({ payload, message });
  }
}

function createService(
  options: { audit?: FakeAudit; repository?: InMemoryRankingRepository } = {},
) {
  const repository = options.repository ?? new InMemoryRankingRepository();
  const audit = options.audit ?? new FakeAudit();
  const prisma = new FakePrisma(repository);
  const logger = new QuietLogger();
  const service = new RankingService(
    prisma as unknown as PrismaService,
    repository,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, repository, audit, prisma, logger };
}

/** Every audit row whose action is the derived-ranking one. */
function rankAudits(audit: FakeAudit): Record<string, unknown>[] {
  return audit.records
    .filter((row) => row.action === RANKING_AUDIT_ACTIONS.RANK_CHANGED)
    .map((row) => row.metadata);
}

/** The result-change audit row, which is the row that is not a rank change. */
function resultAudit(audit: FakeAudit) {
  return audit.records.find((row) => row.action !== RANKING_AUDIT_ACTIONS.RANK_CHANGED);
}

const CREATE_INPUT = {
  athleteProfileId: PROFILE_A,
  eventName: 'National Championship',
  eventDate: new Date('2026-05-01T00:00:00.000Z'),
  points: 10,
};

describe('guard metadata', () => {
  const writeHandlers = [
    StaffRankingController.prototype.create,
    StaffRankingController.prototype.update,
    StaffRankingController.prototype.remove,
  ];
  const readHandler = StaffRankingController.prototype.list;

  it('refuses an ATHLETE session on every write route with a step-up demand', () => {
    for (const handler of writeHandlers) {
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toEqual([Role.ADMIN, Role.OWNER]);
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
    }
  });

  it('keeps the list read staff-only but without a step-up', () => {
    expect(Reflect.getMetadata(ROLES_KEY, readHandler)).toEqual([Role.ADMIN, Role.OWNER]);
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, readHandler)).toBeUndefined();
    expect(Reflect.getMetadata(IS_PUBLIC_KEY, readHandler)).toBeUndefined();
  });

  it('offers no route an athlete could ever be meant to call', () => {
    for (const handler of [...writeHandlers, readHandler]) {
      const path = Reflect.getMetadata(PATH_METADATA, handler) as string;

      expect(path.startsWith('results')).toBe(true);
    }
  });
});

describe('ranking write surface', () => {
  it('accepts no score-like field from the request body at all', () => {
    const base = {
      athleteProfileId: PROFILE_A,
      eventName: 'National Championship',
      eventDate: '2026-05-01',
      points: 10,
    };

    for (const key of ['score', 'rank', 'totalPoints', 'enteredById', 'athleteId']) {
      expect(createCompetitionResultSchema.safeParse({ ...base, [key]: 7 }).success).toBe(false);
      expect(updateCompetitionResultSchema.safeParse({ [key]: 7 }).success).toBe(false);
    }
  });

  it('rejects points outside 0..1000 and non-integer points', () => {
    for (const points of [-1, 1001, 1.5]) {
      expect(() =>
        parseCreateCompetitionResult({ ...CREATE_INPUT, eventDate: '2026-05-01', points }),
      ).toThrow(BadRequestException);
    }
  });

  it('rejects unknown keys, an impossible date and an empty event name', () => {
    const base = {
      athleteProfileId: PROFILE_A,
      eventName: 'Cup',
      eventDate: '2026-05-01',
      points: 10,
    };

    expect(() => parseCreateCompetitionResult({ ...base, extra: 1 })).toThrow(BadRequestException);
    expect(() => parseCreateCompetitionResult({ ...base, eventDate: '2026-02-30' })).toThrow(
      BadRequestException,
    );
    expect(() => parseCreateCompetitionResult({ ...base, eventName: ' ' })).toThrow(
      BadRequestException,
    );
    expect(() => parseUpdateCompetitionResult({ points: 5, bonus: true })).toThrow(
      BadRequestException,
    );
    expect(() => parseUpdateCompetitionResult({})).toThrow(BadRequestException);
  });
});

describe('assignCompetitionRanks', () => {
  it('shares a rank on a tie: 1, 2, 2, 4', () => {
    const ranked = assignCompetitionRanks([
      { athleteProfileId: 'a', totalPoints: 30 },
      { athleteProfileId: 'b', totalPoints: 20 },
      { athleteProfileId: 'c', totalPoints: 20 },
      { athleteProfileId: 'd', totalPoints: 5 },
    ]);

    expect(ranked.map((row) => row.rank)).toEqual([1, 2, 2, 4]);
    expect(ranked.map((row) => row.totalPoints)).toEqual([30, 20, 20, 5]);
  });
});

describe('createResult', () => {
  it('stores the result, recomputes the ranking and audits every changed athlete', async () => {
    const { service, repository, audit, prisma } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);
    repository.seedProfile(PROFILE_B, OTHER_USER_ID);
    repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });
    repository.seedResult({ athleteProfileId: PROFILE_B, points: 5 });
    repository.seedRanking(PROFILE_A, 10, 1);
    repository.seedRanking(PROFILE_B, 5, 2);

    await service.createResult(
      reviewer,
      { ...CREATE_INPUT, athleteProfileId: PROFILE_B, points: 20 },
      CONTEXT,
    );

    // The new result flips the order: A keeps 10, B reaches 25.
    expect(repository.rankings.get(PROFILE_A)).toEqual({
      athleteProfileId: PROFILE_A,
      totalPoints: 10,
      rank: 2,
    });
    expect(repository.rankings.get(PROFILE_B)).toEqual({
      athleteProfileId: PROFILE_B,
      totalPoints: 25,
      rank: 1,
    });

    // One audit row for the result itself, one per athlete the recompute moved.
    expect(audit.records).toHaveLength(3);
    expect(resultAudit(audit)).toMatchObject({
      actorId: STAFF_ID,
      requestId: REQUEST_ID,
      metadata: { athleteProfileId: PROFILE_B, oldPoints: null, newPoints: 20 },
    });
    expect(rankAudits(audit)).toEqual([
      {
        athleteProfileId: PROFILE_B,
        oldPoints: 5,
        newPoints: 25,
        oldRank: 2,
        newRank: 1,
      },
      {
        athleteProfileId: PROFILE_A,
        oldPoints: 10,
        newPoints: 10,
        oldRank: 1,
        newRank: 2,
      },
    ]);
    expect(prisma.transactions[0]).toBeDefined();
  });

  it('takes the advisory lock before reading totals or rankings', async () => {
    const { service, repository } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);

    await service.createResult(reviewer, CREATE_INPUT, CONTEXT);

    // The row is written first, then the lock, then the two reads.
    expect(repository.events.slice(0, 3)).toEqual(['create', 'lock', 'totals']);
    expect(repository.events.indexOf('lock')).toBeLessThan(repository.events.indexOf('rankings'));
  });
});

describe('updateResult', () => {
  it('applies the correction, recomputes and audits old and new points', async () => {
    const { service, repository, audit } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);
    repository.seedProfile(PROFILE_B, OTHER_USER_ID);
    const first = repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });
    const second = repository.seedResult({ athleteProfileId: PROFILE_B, points: 5 });
    repository.seedRanking(PROFILE_A, 10, 1);
    repository.seedRanking(PROFILE_B, 5, 2);

    await service.updateResult(reviewer, second.id, { points: 20 }, CONTEXT);

    expect(repository.results.get(second.id)?.points).toBe(20);
    expect(repository.rankings.get(PROFILE_A)).toEqual({
      athleteProfileId: PROFILE_A,
      totalPoints: 10,
      rank: 2,
    });
    expect(repository.rankings.get(PROFILE_B)).toEqual({
      athleteProfileId: PROFILE_B,
      totalPoints: 20,
      rank: 1,
    });
    expect(resultAudit(audit)).toMatchObject({
      metadata: { resultId: second.id, oldPoints: 5, newPoints: 20 },
    });
    expect(rankAudits(audit)).toEqual([
      { athleteProfileId: PROFILE_B, oldPoints: 5, newPoints: 20, oldRank: 2, newRank: 1 },
      { athleteProfileId: PROFILE_A, oldPoints: 10, newPoints: 10, oldRank: 1, newRank: 2 },
    ]);
    expect(repository.results.get(first.id)?.points).toBe(10);
  });

  it('answers the generic 404 for an unknown id and writes nothing', async () => {
    const { service, repository, audit, prisma } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);

    await expect(
      service.updateResult(reviewer, 'result-404', { points: 1 }, CONTEXT),
    ).rejects.toBeInstanceOf(NotFoundException);

    expect(prisma.transactions).toHaveLength(0);
    expect(audit.records).toHaveLength(0);
  });
});

describe('deleteResult', () => {
  it('removes the result, recomputes and audits the withdrawn points', async () => {
    const { service, repository, audit } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);
    const only = repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });
    repository.seedRanking(PROFILE_A, 10, 1);

    await service.deleteResult(reviewer, only.id, CONTEXT);

    expect(repository.results.has(only.id)).toBe(false);
    expect(repository.rankings.has(PROFILE_A)).toBe(false);
    expect(resultAudit(audit)).toMatchObject({
      metadata: { resultId: only.id, oldPoints: 10, newPoints: null },
    });
    expect(rankAudits(audit)).toEqual([
      { athleteProfileId: PROFILE_A, oldPoints: 10, newPoints: 0, oldRank: 1, newRank: null },
    ]);
  });

  it('still allows withdrawing a row of an athlete whose resume is no longer approved', async () => {
    const { service, repository } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID, 'REJECTED');
    const stale = repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });
    repository.seedRanking(PROFILE_A, 10, 1);

    await service.deleteResult(reviewer, stale.id, CONTEXT);

    expect(repository.results.has(stale.id)).toBe(false);
    expect(repository.rankings.has(PROFILE_A)).toBe(false);
  });
});

describe('fail-closed audit', () => {
  it('rolls the result and the ranking back when the result audit fails', async () => {
    const { service, repository, prisma } = createService({ audit: new FailingAudit() });

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);
    repository.seedRanking(PROFILE_A, 10, 1);

    await expect(service.createResult(reviewer, CREATE_INPUT, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(repository.results.size).toBe(0);
    expect(repository.rankings.get(PROFILE_A)).toEqual({
      athleteProfileId: PROFILE_A,
      totalPoints: 10,
      rank: 1,
    });
    expect(prisma.options[0]).toMatchObject({ maxWait: 5000, timeout: 10000 });
  });

  it('rolls the whole change back when a rank-change audit fails mid-way', async () => {
    const { service, repository } = createService({ audit: new FailingAudit(1) });

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID);
    repository.seedProfile(PROFILE_B, OTHER_USER_ID);
    repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });
    repository.seedResult({ athleteProfileId: PROFILE_B, points: 5 });
    repository.seedRanking(PROFILE_A, 10, 1);
    repository.seedRanking(PROFILE_B, 5, 2);

    await expect(service.createResult(reviewer, CREATE_INPUT, CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(repository.results.size).toBe(2);
    expect(repository.rankings.get(PROFILE_A)).toEqual({
      athleteProfileId: PROFILE_A,
      totalPoints: 10,
      rank: 1,
    });
    expect(repository.rankings.get(PROFILE_B)).toEqual({
      athleteProfileId: PROFILE_B,
      totalPoints: 5,
      rank: 2,
    });
  });
});

describe('self-profile refusal', () => {
  it('refuses entry, correction and withdrawal of the reviewer’s own athlete profile', async () => {
    const { service, repository, audit, prisma, logger } = createService();

    repository.seedProfile(PROFILE_A, STAFF_ID);
    const own = repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });

    await expect(service.createResult(reviewer, CREATE_INPUT, CONTEXT)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    await expect(
      service.updateResult(reviewer, own.id, { points: 5 }, CONTEXT),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.deleteResult(reviewer, own.id, CONTEXT)).rejects.toBeInstanceOf(
      ForbiddenException,
    );

    expect(prisma.transactions).toHaveLength(0);
    expect(audit.records).toHaveLength(0);
    expect(logger.warns).toHaveLength(3);
  });
});

describe('review-status guard', () => {
  it('answers the same generic 404 for a missing and a not-yet-approved profile', async () => {
    for (const status of ['DRAFT', 'PENDING', 'REJECTED'] as const) {
      const { service, repository, prisma, audit } = createService();

      repository.seedProfile(PROFILE_A, ATHLETE_USER_ID, status);

      await expect(service.createResult(reviewer, CREATE_INPUT, CONTEXT)).rejects.toBeInstanceOf(
        NotFoundException,
      );

      expect(prisma.transactions).toHaveLength(0);
      expect(audit.records).toHaveLength(0);
      expect(repository.results.size).toBe(0);
    }
  });

  it('refuses a correction for a result whose athlete is no longer approved', async () => {
    const { service, repository } = createService();

    repository.seedProfile(PROFILE_A, ATHLETE_USER_ID, 'PENDING');
    const stale = repository.seedResult({ athleteProfileId: PROFILE_A, points: 10 });

    await expect(
      service.updateResult(reviewer, stale.id, { points: 5 }, CONTEXT),
    ).rejects.toBeInstanceOf(NotFoundException);

    expect(repository.results.get(stale.id)?.points).toBe(10);
  });
});
