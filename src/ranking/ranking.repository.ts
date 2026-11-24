/**
 * Persistence boundary for competition results and the derived ranking.
 *
 * A result is the only stored score. A ranking row is derived, so this layer
 * offers no "set rank" operation: the service recomputes every row and the
 * repository only persists what the recompute produced.
 */

import type { Prisma, ReviewStatus } from '@prisma/client';

/** DI token so the Prisma implementation can be swapped in tests. */
export const RANKING_REPOSITORY = Symbol('RANKING_REPOSITORY');

/** The columns one competition result may carry. */
export interface CompetitionResultRow {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly eventName: string;
  readonly eventDate: Date;
  readonly points: number;
  readonly enteredById: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/**
 * What a correction or a deletion needs: the row plus the account behind the
 * profile, so the service can refuse a staff member's own profile, and the
 * review status, so a non-approved athlete is the generic 404.
 */
export interface CompetitionResultTarget extends CompetitionResultRow {
  readonly ownerUserId: string;
  readonly reviewStatus: ReviewStatus;
}

/** What an entry needs. `enteredById` is stamped from the token. */
export interface NewCompetitionResult {
  readonly athleteProfileId: string;
  readonly eventName: string;
  readonly eventDate: Date;
  readonly points: number;
  readonly enteredById: string;
}

/** Only the correctable fields; there is no athlete and no rank here. */
export interface CompetitionResultPatch {
  readonly eventName?: string;
  readonly eventDate?: Date;
  readonly points?: number;
}

/** One athlete and the sum of their approved results. */
export interface RankingTotal {
  readonly athleteProfileId: string;
  readonly totalPoints: number;
}

/** One derived leaderboard row. */
export interface RankingRow extends RankingTotal {
  readonly rank: number;
}

/** The one fact the entry check needs from a profile. */
export interface RankingProfile {
  readonly id: string;
  readonly userId: string;
  readonly reviewStatus: ReviewStatus;
}

export interface RankingRepository {
  /** One profile by id, whatever its review status; `null` when absent. */
  findProfile(athleteProfileId: string): Promise<RankingProfile | null>;

  /** One result by id with its profile's owner and review status. */
  findResult(resultId: string): Promise<CompetitionResultTarget | null>;

  createResult(
    input: NewCompetitionResult,
    tx: Prisma.TransactionClient,
  ): Promise<CompetitionResultRow>;

  /** One conditional UPDATE by id; the number of rows changed. */
  updateResult(
    resultId: string,
    patch: CompetitionResultPatch,
    tx: Prisma.TransactionClient,
  ): Promise<number>;

  /** One DELETE by id; the number of rows changed. */
  deleteResult(resultId: string, tx: Prisma.TransactionClient): Promise<number>;

  /**
   * Results for one athlete or all of them, newest event first, at most
   * `limit + 1` rows: the extra row is how the service knows there is a next
   * page without a second query.
   */
  listResults(
    athleteProfileId: string | undefined,
    limit: number,
    cursor: string | undefined,
  ): Promise<CompetitionResultRow[]>;

  /**
   * The transaction-level advisory lock every recompute holds, so two staff
   * changes cannot compute a ranking from interleaved reads. Held until the
   * surrounding transaction ends.
   */
  lock(tx: Prisma.TransactionClient): Promise<void>;

  /** SUM(points) per athlete whose resume is APPROVED. */
  sumApprovedTotals(tx: Prisma.TransactionClient): Promise<RankingTotal[]>;

  /** Every stored ranking row, for the diff the recompute writes. */
  listRankings(tx: Prisma.TransactionClient): Promise<RankingRow[]>;

  upsertRanking(row: RankingRow, tx: Prisma.TransactionClient): Promise<void>;

  /** Drops the row of an athlete whose last result is gone. */
  deleteRanking(athleteProfileId: string, tx: Prisma.TransactionClient): Promise<void>;
}
