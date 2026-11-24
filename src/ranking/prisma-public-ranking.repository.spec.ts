import type { PrismaService } from '../database/prisma.service';
import { PrismaPublicRankingRepository } from './prisma-public-ranking.repository';

/**
 * The read predicate is the guarantee: the APPROVED join is part of the query,
 * so a stale ranking row cannot surface. This spec pins the generated arguments;
 * PostgreSQL is not involved.
 */

interface FindManyArgs {
  where: Record<string, unknown>;
  orderBy: unknown;
  take: number;
  cursor?: { athleteProfileId: string };
  skip?: number;
  select: Record<string, boolean>;
}

interface FindFirstArgs {
  where: Record<string, unknown>;
  select: Record<string, boolean>;
}

const ROW = { athleteProfileId: 'profile-a', totalPoints: 42, rank: 3 };

function createPrisma(rows: unknown = [ROW], found: unknown = ROW) {
  return {
    athleteRanking: {
      findMany: jest.fn(async () => rows),
      findFirst: jest.fn(async () => found),
    },
  };
}

function listArgs(prisma: ReturnType<typeof createPrisma>): FindManyArgs | undefined {
  return (prisma.athleteRanking.findMany.mock.calls as unknown as FindManyArgs[][])[0]?.[0];
}

function findArgs(prisma: ReturnType<typeof createPrisma>): FindFirstArgs | undefined {
  return (prisma.athleteRanking.findFirst.mock.calls as unknown as FindFirstArgs[][])[0]?.[0];
}

describe('PrismaPublicRankingRepository', () => {
  it('lists approved athletes by rank then id, one row beyond the page', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicRankingRepository(prisma as unknown as PrismaService);

    await expect(repository.listApproved(20, undefined)).resolves.toEqual([ROW]);

    const args = listArgs(prisma);

    expect(args?.where).toEqual({ athleteProfile: { reviewStatus: 'APPROVED' } });
    expect(args?.orderBy).toEqual([{ rank: 'asc' }, { athleteProfileId: 'asc' }]);
    expect(args?.take).toBe(21);
    expect(args?.cursor).toBeUndefined();
    // Only the three public columns are selected; no user, email or result join.
    expect(args?.select).toEqual({ athleteProfileId: true, totalPoints: true, rank: true });
  });

  it('resumes at the cursor row and skips it', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicRankingRepository(prisma as unknown as PrismaService);

    await repository.listApproved(2, 'profile-b');

    expect(listArgs(prisma)?.take).toBe(3);
    expect(listArgs(prisma)?.cursor).toEqual({ athleteProfileId: 'profile-b' });
    expect(listArgs(prisma)?.skip).toBe(1);
  });

  it('finds one athlete only when that profile is still approved', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicRankingRepository(prisma as unknown as PrismaService);

    await expect(repository.findApproved('profile-a')).resolves.toEqual(ROW);

    expect(prisma.athleteRanking.findFirst).toHaveBeenCalledTimes(1);
    expect(findArgs(prisma)?.where).toEqual({
      athleteProfileId: 'profile-a',
      athleteProfile: { reviewStatus: 'APPROVED' },
    });
    expect(findArgs(prisma)?.select).toEqual({
      athleteProfileId: true,
      totalPoints: true,
      rank: true,
    });
  });

  it('reports a non-approved, unranked or missing profile the same way', async () => {
    const prisma = createPrisma([], null);
    const repository = new PrismaPublicRankingRepository(prisma as unknown as PrismaService);

    await expect(repository.findApproved('profile-a')).resolves.toBeNull();
  });
});
