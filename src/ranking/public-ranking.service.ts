import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PublicRankingQuery } from './public-ranking.dto';
import {
  PUBLIC_RANKING_REPOSITORY,
  type PublicRankingRepository,
  type PublicRankingRow,
} from './public-ranking.repository';

/**
 * How long a public answer may be cached. Short on purpose: an approval can be
 * withdrawn at any time, so a stale leaderboard must expire quickly.
 */
export const PUBLIC_RANKING_CACHE_SECONDS = 30;

/** One leaderboard entry, exactly as it leaves the API. */
export interface PublicRankingItem {
  readonly athleteProfileId: string;
  readonly totalPoints: number;
  readonly rank: number;
}

export interface PublicRankingPage {
  readonly items: PublicRankingItem[];
  /** `null` on the last page; otherwise the cursor of the next one. */
  readonly nextCursor: string | null;
}

/**
 * Rebuilds the row field by field, so an extra column added to the table can
 * never leak through this surface by accident.
 */
function toItem(row: PublicRankingRow): PublicRankingItem {
  return {
    athleteProfileId: row.athleteProfileId,
    totalPoints: row.totalPoints,
    rank: row.rank,
  };
}

/**
 * The read-only public ranking.
 *
 * No write, no audit, no identity: the only facts returned are the profile id
 * and the two derived numbers. The APPROVED check lives in the repository
 * predicate, so a profile that is no longer approved vanishes immediately even
 * when its ranking row has not been recomputed.
 */
@Injectable()
export class PublicRankingService {
  constructor(
    @Inject(PUBLIC_RANKING_REPOSITORY) private readonly repository: PublicRankingRepository,
  ) {}

  /** One page, ties keeping the rank the recompute stored for them. */
  async list(query: PublicRankingQuery): Promise<PublicRankingPage> {
    const limit = query.limit;
    const rows = await this.repository.listApproved(limit, query.cursor);
    const items = rows.slice(0, limit).map(toItem);
    const last = items[items.length - 1];

    return {
      items,
      nextCursor: rows.length > limit && last !== undefined ? last.athleteProfileId : null,
    };
  }

  /**
   * One athlete's rank and total. Missing, unranked and non-approved are the
   * same generic 404: the caller learns nothing about why there is no row.
   */
  async read(athleteProfileId: string): Promise<PublicRankingItem> {
    const row = await this.repository.findApproved(athleteProfileId);

    if (row === null) throw new NotFoundException();

    return toItem(row);
  }
}
