/**
 * Persistence boundary for the public leaderboard read.
 *
 * Separate from `RankingRepository` on purpose: this layer only reads derived
 * rows, never writes one, and it has no way to return an identity, an entered-by
 * account or an individual result. The APPROVED predicate is part of every
 * query, so a profile that is un-approved disappears from the leaderboard on the
 * next read even while its ranking row is still stored.
 */

/** DI token so the Prisma implementation can be swapped in tests. */
export const PUBLIC_RANKING_REPOSITORY = Symbol('PUBLIC_RANKING_REPOSITORY');

/** One leaderboard row: the two derived facts plus the profile it belongs to. */
export interface PublicRankingRow {
  readonly athleteProfileId: string;
  readonly totalPoints: number;
  readonly rank: number;
}

export interface PublicRankingRepository {
  /**
   * One page of approved athletes, ordered by rank and then profile id, at most
   * `limit + 1` rows: the extra row is how the service knows a page follows.
   * The cursor is the previous page's last athlete profile id.
   */
  listApproved(limit: number, cursor: string | undefined): Promise<PublicRankingRow[]>;

  /**
   * The row of one approved athlete. A missing profile, an unranked one and a
   * non-approved one are all `null`; the service turns that into one generic 404.
   */
  findApproved(athleteProfileId: string): Promise<PublicRankingRow | null>;
}
