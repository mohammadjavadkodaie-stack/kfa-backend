import { Injectable } from '@nestjs/common';
import type { CompanyKind, Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import type { PublicCompanyRepository, PublicCompanyRow } from './public-company.repository';

/**
 * The only columns a public answer may carry. The select is explicit, so a
 * column added to `companies` later cannot leak through this surface by
 * accident; the staff-only legal identity is never read here at all.
 */
const PUBLIC_COMPANY_FIELDS = {
  slug: true,
  displayName: true,
  country: true,
  kind: true,
  description: true,
  websiteUrl: true,
} as const;

type PublicCompanyModel = Prisma.CompanyGetPayload<{ select: typeof PUBLIC_COMPANY_FIELDS }>;

@Injectable()
export class PrismaPublicCompanyRepository implements PublicCompanyRepository {
  constructor(private readonly prisma: PrismaService) {}

  async listAlphabetical(
    limit: number,
    cursor: string | undefined,
    kind?: CompanyKind,
  ): Promise<PublicCompanyRow[]> {
    // The unique slug is a total order, so the page boundary is stable between
    // two reads. The cursor is a keyset bound (`slug > cursor`), not Prisma's
    // `cursor` option: the range read keeps working when a row between the
    // cursor and the page is soft-deleted.
    const rows: PublicCompanyModel[] = await this.prisma.company.findMany({
      where: {
        deletedAt: null,
        ...(kind === undefined ? {} : { kind }),
        ...(cursor === undefined ? {} : { slug: { gt: cursor } }),
      },
      orderBy: { slug: 'asc' },
      take: limit + 1,
      select: PUBLIC_COMPANY_FIELDS,
    });

    return rows;
  }

  async findActiveBySlug(slug: string): Promise<PublicCompanyRow | null> {
    // findFirst, not findUnique: `deletedAt IS NULL` must be part of the
    // predicate, so a retired company is not found at all.
    const row: PublicCompanyModel | null = await this.prisma.company.findFirst({
      where: { slug, deletedAt: null },
      select: PUBLIC_COMPANY_FIELDS,
    });

    return row;
  }
}
