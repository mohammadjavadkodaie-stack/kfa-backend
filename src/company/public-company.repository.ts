/**
 * Persistence boundary for the public company card.
 *
 * Separate from `CompanyRepository` on purpose: a row here can only carry the
 * six public columns, so the legal identity of a company has no public reader at
 * all. The `deletedAt IS NULL` predicate belongs to every query in this port,
 * which is how a soft-deleted company disappears from the list and becomes an
 * ordinary 404 on the single read.
 */

import type { CompanyKind } from '@prisma/client';

/** DI token so the Prisma implementation can be swapped in tests. */
export const PUBLIC_COMPANY_REPOSITORY = Symbol('PUBLIC_COMPANY_REPOSITORY');

/** One public company card: the visible face and nothing else. */
export interface PublicCompanyRow {
  readonly slug: string;
  readonly displayName: string;
  readonly country: string;
  readonly kind: CompanyKind;
  readonly description: string | null;
  readonly websiteUrl: string | null;
}

export interface PublicCompanyRepository {
  /**
   * One page of live companies ordered by slug, at most `limit + 1` rows: the
   * extra row is how the service knows a page follows without a second query.
   * The cursor is the previous page's last slug and is applied as `slug > cursor`.
   */
  listAlphabetical(
    limit: number,
    cursor: string | undefined,
    kind?: CompanyKind,
  ): Promise<PublicCompanyRow[]>;

  /**
   * One live company by slug. Missing and soft-deleted are both `null`; the
   * service turns either into the same generic 404.
   */
  findActiveBySlug(slug: string): Promise<PublicCompanyRow | null>;
}
