import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';
import { DEFAULT_RANKING_PAGE_SIZE, MAX_RANKING_PAGE_SIZE } from './ranking.dto';

/**
 * The wire gate for the public leaderboard.
 *
 * `strictObject` refuses any key the schema does not declare, so a misspelled or
 * unknown parameter is the generic 400 before a rate-limit counter is spent.
 * The page is hard-capped: an anonymous caller never chooses how much leaves the
 * server in one response.
 */
export const publicRankingQuerySchema = z.strictObject({
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_RANKING_PAGE_SIZE)
    .default(DEFAULT_RANKING_PAGE_SIZE),
  /** The `athleteProfileId` of the last item of the previous page. */
  cursor: z.uuid().optional(),
});

export type PublicRankingQuery = z.infer<typeof publicRankingQuerySchema>;

export function parsePublicRankingQuery(query: unknown): PublicRankingQuery {
  const parsed = publicRankingQuerySchema.safeParse(query ?? {});

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/** The path segment; malformed is a 400 before any lookup, which discloses nothing. */
export function parsePublicRankingProfileId(value: unknown): string {
  const parsed = z.uuid().safeParse(value);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}
