/**
 * Persistence boundary for company profiles.
 *
 * Only the staff routes reach this layer today, so a row carries both the
 * public face and the staff-only legal identity. A later public read must select
 * the public columns explicitly; it never widens `CompanyRow` itself.
 *
 * The delete is an UPDATE: `softDelete` only moves a live row, so a repeated
 * delete changes nothing and the service can answer the same generic 404 as for
 * an id that never existed.
 */

import type { CompanyKind, Prisma } from '@prisma/client';

/** DI token so the Prisma implementation can be swapped in tests. */
export const COMPANY_REPOSITORY = Symbol('COMPANY_REPOSITORY');

/** The columns one company may carry. */
export interface CompanyRow {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly country: string;
  readonly kind: CompanyKind;
  readonly description: string | null;
  readonly websiteUrl: string | null;
  readonly legalName: string;
  readonly tradeRegistryNumber: string | null;
  readonly mersisNumber: string | null;
  readonly taxNumber: string | null;
  readonly taxOffice: string | null;
  readonly chamberName: string | null;
  readonly chamberRegisteredAt: Date | null;
  readonly naceCode: string | null;
  readonly address: string | null;
  readonly contactEmail: string | null;
  readonly createdById: string;
  readonly updatedById: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly deletedAt: Date | null;
}

/** What a creation needs; the two staff columns come from the verified token. */
export interface NewCompany {
  readonly slug: string;
  readonly displayName: string;
  readonly country: string;
  readonly kind: CompanyKind;
  readonly description?: string | null;
  readonly websiteUrl?: string | null;
  readonly legalName: string;
  readonly tradeRegistryNumber?: string | null;
  readonly mersisNumber?: string | null;
  readonly taxNumber?: string | null;
  readonly taxOffice?: string | null;
  readonly chamberName?: string | null;
  readonly chamberRegisteredAt?: Date | null;
  readonly naceCode?: string | null;
  readonly address?: string | null;
  readonly contactEmail?: string | null;
  readonly createdById: string;
  readonly updatedById: string;
}

/** Only the correctable fields: the slug is fixed at creation. */
export interface CompanyPatch {
  readonly displayName?: string;
  readonly country?: string;
  readonly kind?: CompanyKind;
  readonly description?: string | null;
  readonly websiteUrl?: string | null;
  readonly legalName?: string;
  readonly tradeRegistryNumber?: string | null;
  readonly mersisNumber?: string | null;
  readonly taxNumber?: string | null;
  readonly taxOffice?: string | null;
  readonly chamberName?: string | null;
  readonly chamberRegisteredAt?: Date | null;
  readonly naceCode?: string | null;
  readonly address?: string | null;
  readonly contactEmail?: string | null;
  readonly updatedById: string;
}

export interface CompanyRepository {
  create(input: NewCompany, tx: Prisma.TransactionClient): Promise<CompanyRow>;

  /** One conditional UPDATE of a live row; the number of rows changed. */
  update(companyId: string, patch: CompanyPatch, tx: Prisma.TransactionClient): Promise<number>;

  /**
   * One conditional UPDATE that stamps `deletedAt` on a still-live row; the
   * number of rows changed, so 0 means missing or already deleted.
   */
  softDelete(
    companyId: string,
    updatedById: string,
    deletedAt: Date,
    tx: Prisma.TransactionClient,
  ): Promise<number>;

  /** One live company by id; `null` when absent or soft-deleted. */
  findActiveById(companyId: string, tx?: Prisma.TransactionClient): Promise<CompanyRow | null>;

  /**
   * Live companies, newest first, at most `limit + 1` rows: the extra row is how
   * the service knows there is a next page without a second query.
   */
  listActive(limit: number, cursor: string | undefined): Promise<CompanyRow[]>;
}
