import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import type { PublicRankingRepository, PublicRankingRow } from './public-ranking.repository';

/** The three columns a public row may carry; nothing else is selected. */
const PUBLIC_RANKING_FIELDS = {
  athleteProfileId: true,
  totalPoints: true,
  rank: true,
} as const;

/** The review status is a join predicate, never a column the caller filters later. */
const APPROVED_ONLY = { athleteProfile: { reviewStatus: 'APPROVED' } } as const;

@Injectable()
export class PrismaPublicRankingRepository implements PublicRankingRepository {
  constructor(private readonly prisma: PrismaService) {}

  async listApproved(limit: number, cursor: string | undefined): Promise<PublicRankingRow[]> {
    // `rank` then the unique id is a total order, so a page boundary is stable
    // between two reads even when two athletes share a rank.
    return this.prisma.athleteRanking.findMany({
      where: APPROVED_ONLY,
      orderBy: [{ rank: 'asc' }, { athleteProfileId: 'asc' }],
      take: limit + 1,
      ...(cursor === undefined ? {} : { cursor: { athleteProfileId: cursor }, skip: 1 }),
      select: PUBLIC_RANKING_FIELDS,
    });
  }

  async findApproved(athleteProfileId: string): Promise<PublicRankingRow | null> {
    // findFirst, not findUnique: the review status must be part of the predicate
    // so a stale row for an un-approved profile is not found at all.
    return this.prisma.athleteRanking.findFirst({
      where: { athleteProfileId, ...APPROVED_ONLY },
      select: PUBLIC_RANKING_FIELDS,
    });
  }
}
