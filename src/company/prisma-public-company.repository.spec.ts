import type { PrismaService } from '../database/prisma.service';
import { PrismaPublicCompanyRepository } from './prisma-public-company.repository';

/**
 * The read predicate and the select are the guarantee: `deletedAt IS NULL` is
 * part of every query and only the six public columns are ever asked for. This
 * spec pins the generated arguments; PostgreSQL is not involved.
 */

interface FindManyArgs {
  where: Record<string, unknown>;
  orderBy: unknown;
  take: number;
  cursor?: unknown;
  skip?: unknown;
  select: Record<string, boolean>;
}

interface FindFirstArgs {
  where: Record<string, unknown>;
  select: Record<string, boolean>;
}

const ROW = {
  slug: 'acme-rockets',
  displayName: 'Acme Rockets',
  country: 'TR',
  kind: 'SPONSOR',
  description: null,
  websiteUrl: 'https://acme.example',
};

/** The whitelist: no id, no legal identity, no attribution, no timestamps. */
const PUBLIC_SELECT = {
  slug: true,
  displayName: true,
  country: true,
  kind: true,
  description: true,
  websiteUrl: true,
};

function createPrisma(rows: unknown = [ROW], found: unknown = ROW) {
  return {
    company: {
      findMany: jest.fn(async () => rows),
      findFirst: jest.fn(async () => found),
    },
  };
}

function listArgs(prisma: ReturnType<typeof createPrisma>): FindManyArgs | undefined {
  return (prisma.company.findMany.mock.calls as unknown as FindManyArgs[][])[0]?.[0];
}

function findArgs(prisma: ReturnType<typeof createPrisma>): FindFirstArgs | undefined {
  return (prisma.company.findFirst.mock.calls as unknown as FindFirstArgs[][])[0]?.[0];
}

describe('PrismaPublicCompanyRepository', () => {
  it('lists live companies by slug, one row beyond the page, with an explicit select', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicCompanyRepository(prisma as unknown as PrismaService);

    await expect(repository.listAlphabetical(20, undefined)).resolves.toEqual([ROW]);

    const args = listArgs(prisma);

    expect(args?.where).toEqual({ deletedAt: null });
    expect(args?.orderBy).toEqual({ slug: 'asc' });
    expect(args?.take).toBe(21);
    expect(args?.select).toEqual(PUBLIC_SELECT);
    // No Prisma cursor option: the page is a keyset range read.
    expect(args?.cursor).toBeUndefined();
    expect(args?.skip).toBeUndefined();
  });

  it('resumes with `slug > cursor` in the where clause, not the cursor option', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicCompanyRepository(prisma as unknown as PrismaService);

    await repository.listAlphabetical(2, 'acme-rockets');

    const args = listArgs(prisma);

    expect(args?.take).toBe(3);
    expect(args?.where).toEqual({ deletedAt: null, slug: { gt: 'acme-rockets' } });
    expect(args?.cursor).toBeUndefined();
    expect(args?.skip).toBeUndefined();
  });

  it('narrows to one kind without dropping the live-row predicate', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicCompanyRepository(prisma as unknown as PrismaService);

    await repository.listAlphabetical(20, undefined, 'SPONSOR');

    expect(listArgs(prisma)?.where).toEqual({ deletedAt: null, kind: 'SPONSOR' });
    expect(listArgs(prisma)?.select).toEqual(PUBLIC_SELECT);
  });

  it('finds one company only while it is still live', async () => {
    const prisma = createPrisma();
    const repository = new PrismaPublicCompanyRepository(prisma as unknown as PrismaService);

    await expect(repository.findActiveBySlug('acme-rockets')).resolves.toEqual(ROW);

    expect(prisma.company.findFirst).toHaveBeenCalledTimes(1);
    expect(findArgs(prisma)?.where).toEqual({ slug: 'acme-rockets', deletedAt: null });
    expect(findArgs(prisma)?.select).toEqual(PUBLIC_SELECT);
  });

  it('reports a missing or soft-deleted company the same way', async () => {
    const prisma = createPrisma([], null);
    const repository = new PrismaPublicCompanyRepository(prisma as unknown as PrismaService);

    await expect(repository.findActiveBySlug('acme-rockets')).resolves.toBeNull();
  });
});
