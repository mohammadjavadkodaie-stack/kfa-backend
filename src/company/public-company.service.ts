import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { isPublicCompanySlug, type PublicCompanyQuery } from './public-company.dto';
import {
  PUBLIC_COMPANY_REPOSITORY,
  type PublicCompanyRepository,
  type PublicCompanyRow,
} from './public-company.repository';

/**
 * How long a public company answer may be cached. Short on purpose: a profile
 * can be corrected or retired at any time, so a stale card must expire quickly.
 */
export const PUBLIC_COMPANY_CACHE_SECONDS = 30;

/** One public company card, exactly as it leaves the API. */
export interface PublicCompanyItem {
  readonly slug: string;
  readonly displayName: string;
  readonly country: string;
  readonly kind: PublicCompanyRow['kind'];
  readonly description: string | null;
  readonly websiteUrl: string | null;
}

export interface PublicCompanyPage {
  readonly items: PublicCompanyItem[];
  /** `null` on the last page; otherwise the slug the next page starts after. */
  readonly nextCursor: string | null;
}

/**
 * Rebuilds the row field by field, so an extra column added to the table - or a
 * repository that returns more than the select asked for - can never leak
 * through this surface by accident.
 */
function toItem(row: PublicCompanyRow): PublicCompanyItem {
  return {
    slug: row.slug,
    displayName: row.displayName,
    country: row.country,
    kind: row.kind,
    description: row.description,
    websiteUrl: row.websiteUrl,
  };
}

/**
 * The read-only public company card.
 *
 * No write, no audit, no identity: the six public columns are the whole answer.
 * The `deletedAt` predicate lives in the repository, so a retired company
 * disappears from the list and reads as not found without any extra check here.
 */
@Injectable()
export class PublicCompanyService {
  constructor(
    @Inject(PUBLIC_COMPANY_REPOSITORY) private readonly repository: PublicCompanyRepository,
  ) {}

  /** One page, alphabetical by slug; the cursor is the previous last slug. */
  async list(query: PublicCompanyQuery): Promise<PublicCompanyPage> {
    const limit = query.limit;
    const rows = await this.repository.listAlphabetical(limit, query.cursor, query.kind);
    const items = rows.slice(0, limit).map(toItem);
    const last = items[items.length - 1];

    return {
      items,
      // The extra row was read but never returned: it only proves a page follows.
      nextCursor: rows.length > limit && last !== undefined ? last.slug : null,
    };
  }

  /**
   * One live company. Missing, soft-deleted and malformed slugs are the same
   * generic 404: a malformed slug is not a 400 here, and nothing about the
   * company's history is revealed by asking.
   */
  async read(slug: string): Promise<PublicCompanyItem> {
    if (!isPublicCompanySlug(slug)) throw new NotFoundException();

    const row = await this.repository.findActiveBySlug(slug);

    if (row === null) throw new NotFoundException();

    return toItem(row);
  }
}
