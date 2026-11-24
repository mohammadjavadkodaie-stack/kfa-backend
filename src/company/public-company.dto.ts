import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';
import { COMPANY_KINDS, DEFAULT_COMPANY_PAGE_SIZE, MAX_COMPANY_PAGE_SIZE } from './company.dto';

/**
 * The wire gate for the public company reads.
 *
 * `strictObject` refuses any key the schema does not declare, so a misspelled or
 * unknown parameter is the generic 400 before a rate-limit counter is spent. The
 * page is hard-capped: an anonymous caller never chooses how much leaves the
 * server in one response.
 *
 * The slug is the same immutable identity the staff create; the pattern is the
 * one `createCompanySchema` enforces, so a cursor or a path segment that is not
 * a slug is refused here (list) or answered as a 404 (single read).
 */

/** Lowercase `[a-z0-9-]`, 3-60 characters: the company's public identity. */
export const PUBLIC_COMPANY_SLUG_PATTERN = /^[a-z0-9-]{3,60}$/;

export const publicCompanyQuerySchema = z.strictObject({
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_COMPANY_PAGE_SIZE)
    .default(DEFAULT_COMPANY_PAGE_SIZE),
  /** The `slug` of the last company of the previous page. */
  cursor: z.string().regex(PUBLIC_COMPANY_SLUG_PATTERN).optional(),
  kind: z.enum(COMPANY_KINDS).optional(),
});

export type PublicCompanyQuery = z.infer<typeof publicCompanyQuerySchema>;

export function parsePublicCompanyQuery(query: unknown): PublicCompanyQuery {
  const parsed = publicCompanyQuerySchema.safeParse(query ?? {});

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * The shape check of the path segment, not a 400: the read route answers a
 * malformed slug with the same generic 404 as a missing company, so nothing can
 * be told apart by probing the route.
 */
export function isPublicCompanySlug(value: unknown): value is string {
  return typeof value === 'string' && PUBLIC_COMPANY_SLUG_PATTERN.test(value);
}
