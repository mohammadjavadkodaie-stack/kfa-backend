import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
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

/**
 * Advisory-lock coordinates for the ranking recompute (`pg_advisory_xact_lock`).
 *
 * 0x4B4641 is "KFA" in ASCII, the same namespace the audit chain uses; the second
 * key is different, so the ranking lock and the audit-chain lock never wait on
 * each other. Constant across instances, which is what serialises concurrent
 * staff changes into one recompute at a time.
 */
export const RANKING_LOCK_NAMESPACE = 4_933_185;
export const RANKING_LOCK_ID = 2;

const RESULT_FIELDS = {
  id: true,
  athleteProfileId: true,
  eventName: true,
  eventDate: true,
  points: true,
  enteredById: true,
  createdAt: true,
  updatedAt: true,
} as const;

const TARGET_FIELDS = {
  ...RESULT_FIELDS,
  athleteProfile: { select: { userId: true, reviewStatus: true } },
} as const;

type ResultModel = Prisma.CompetitionResultGetPayload<{ select: typeof RESULT_FIELDS }>;
type TargetModel = Prisma.CompetitionResultGetPayload<{ select: typeof TARGET_FIELDS }>;

@Injectable()
export class PrismaRankingRepository implements RankingRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findProfile(athleteProfileId: string): Promise<RankingProfile | null> {
    const row = await this.prisma.athleteProfile.findUnique({
      where: { id: athleteProfileId },
      select: { id: true, userId: true, reviewStatus: true },
    });

    return row;
  }

  async findResult(resultId: string): Promise<CompetitionResultTarget | null> {
    const row: TargetModel | null = await this.prisma.competitionResult.findUnique({
      where: { id: resultId },
      select: TARGET_FIELDS,
    });

    if (row === null) return null;

    return {
      id: row.id,
      athleteProfileId: row.athleteProfileId,
      eventName: row.eventName,
      eventDate: row.eventDate,
      points: row.points,
      enteredById: row.enteredById,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      ownerUserId: row.athleteProfile.userId,
      reviewStatus: row.athleteProfile.reviewStatus,
    };
  }

  async createResult(
    input: NewCompetitionResult,
    tx: Prisma.TransactionClient,
  ): Promise<CompetitionResultRow> {
    const row: ResultModel = await tx.competitionResult.create({
      data: {
        athleteProfileId: input.athleteProfileId,
        eventName: input.eventName,
        eventDate: input.eventDate,
        points: input.points,
        enteredById: input.enteredById,
      },
      select: RESULT_FIELDS,
    });

    return row;
  }

  async updateResult(
    resultId: string,
    patch: CompetitionResultPatch,
    tx: Prisma.TransactionClient,
  ): Promise<number> {
    const result = await tx.competitionResult.updateMany({
      where: { id: resultId },
      data: patch,
    });

    return result.count;
  }

  async deleteResult(resultId: string, tx: Prisma.TransactionClient): Promise<number> {
    const result = await tx.competitionResult.deleteMany({ where: { id: resultId } });

    return result.count;
  }

  async listResults(
    athleteProfileId: string | undefined,
    limit: number,
    cursor: string | undefined,
  ): Promise<CompetitionResultRow[]> {
    // A total order (event, then arrival, then the unique id) makes the answer
    // stable between two reads; the cursor page resumes at exactly the row it
    // was handed.
    const rows: ResultModel[] = await this.prisma.competitionResult.findMany({
      where: athleteProfileId === undefined ? {} : { athleteProfileId },
      orderBy: [{ eventDate: 'desc' }, { createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      ...(cursor === undefined ? {} : { cursor: { id: cursor }, skip: 1 }),
      select: RESULT_FIELDS,
    });

    return rows;
  }

  async lock(tx: Prisma.TransactionClient): Promise<void> {
    // `pg_advisory_xact_lock` returns `void`; $executeRaw is the correct entry
    // point because $queryRaw tries to deserialize the returned column.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${RANKING_LOCK_NAMESPACE}::int, ${RANKING_LOCK_ID}::int)`;
  }

  async sumApprovedTotals(tx: Prisma.TransactionClient): Promise<RankingTotal[]> {
    // The APPROVED predicate is part of the aggregate, so a rejected or pending
    // athlete never enters the leaderboard even if old results still exist.
    const groups = await tx.competitionResult.groupBy({
      by: ['athleteProfileId'],
      where: { athleteProfile: { reviewStatus: 'APPROVED' } },
      _sum: { points: true },
    });

    return groups.map((group) => ({
      athleteProfileId: group.athleteProfileId,
      totalPoints: group._sum.points ?? 0,
    }));
  }

  async listRankings(tx: Prisma.TransactionClient): Promise<RankingRow[]> {
    return tx.athleteRanking.findMany({
      select: { athleteProfileId: true, totalPoints: true, rank: true },
    });
  }

  async upsertRanking(row: RankingRow, tx: Prisma.TransactionClient): Promise<void> {
    await tx.athleteRanking.upsert({
      where: { athleteProfileId: row.athleteProfileId },
      create: {
        athleteProfileId: row.athleteProfileId,
        totalPoints: row.totalPoints,
        rank: row.rank,
      },
      update: { totalPoints: row.totalPoints, rank: row.rank },
    });
  }

  async deleteRanking(athleteProfileId: string, tx: Prisma.TransactionClient): Promise<void> {
    await tx.athleteRanking.deleteMany({ where: { athleteProfileId } });
  }
}
