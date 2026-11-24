import { BadRequestException } from '@nestjs/common';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { z } from 'zod';

/**
 * The wire gate for staff-entered competition results.
 *
 * Two things are deliberately absent from every schema here:
 *
 * 1. an athlete identity - a result names the profile it belongs to, but the
 *    caller is always a staff principal resolved from the token, never an
 *    athlete sending their own score;
 * 2. a derived value - no `rank`, no `totalPoints` and no `score` alias is
 *    accepted, and `strictObject` turns one into the generic 400 instead of
 *    ignoring it. The ranking is only ever computed on the server.
 */

/** A page of results, when the caller does not say how much it wants. */
export const DEFAULT_RANKING_PAGE_SIZE = 20;

/** The hard cap: an event list is small, and a huge page buys a caller nothing. */
export const MAX_RANKING_PAGE_SIZE = 50;

/** The column cap of `event_name`; enforced here and in the database. */
export const MAX_EVENT_NAME_LENGTH = 120;

/** The score range, enforced by the DTO, the service and a CHECK constraint. */
export const MIN_RESULT_POINTS = 0;
export const MAX_RESULT_POINTS = 1_000;

/** `YYYY-MM-DD`, and a real calendar day: 2026-02-30 is not one. */
const eventDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const parsed = new Date(`${value}T00:00:00.000Z`);

    return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
  })
  .transform((value) => new Date(`${value}T00:00:00.000Z`));

/** Trimmed, so a name of spaces is no name. */
const eventNameSchema = z
  .string()
  .transform((value) => value.trim())
  .pipe(z.string().min(1).max(MAX_EVENT_NAME_LENGTH));

const pointsSchema = z.number().int().min(MIN_RESULT_POINTS).max(MAX_RESULT_POINTS);

/**
 * `POST /staff/ranking/results`.
 *
 * The staff member is not a field: the entered-by column is stamped from the
 * verified token. The profile is chosen by staff, and the service refuses one
 * whose resume is not APPROVED.
 */
export const createCompetitionResultSchema = z.strictObject({
  athleteProfileId: z.uuid(),
  eventName: eventNameSchema,
  eventDate: eventDateSchema,
  points: pointsSchema,
});

export type CreateCompetitionResultWire = z.infer<typeof createCompetitionResultSchema>;

/** The wire gate: a body outside the schema is the generic 400. */
export function parseCreateCompetitionResult(body: unknown): CreateCompetitionResultWire {
  const parsed = createCompetitionResultSchema.safeParse(body);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * `PATCH /staff/ranking/results/:id`.
 *
 * At most the three correctable facts; an empty body is not a patch. There is no
 * athlete to move a result to, and no way to set a rank.
 */
export const updateCompetitionResultSchema = z
  .strictObject({
    eventName: eventNameSchema.optional(),
    eventDate: eventDateSchema.optional(),
    points: pointsSchema.optional(),
  })
  .refine((input) => Object.keys(input).length > 0);

export type UpdateCompetitionResultWire = z.infer<typeof updateCompetitionResultSchema>;

export function parseUpdateCompetitionResult(body: unknown): UpdateCompetitionResultWire {
  const parsed = updateCompetitionResultSchema.safeParse(body);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * `GET /staff/ranking/results?athleteProfileId=&limit=&cursor=`.
 *
 * Every field is declared, so a misspelled or unknown parameter is the generic
 * 400 instead of being silently ignored.
 */
export class RankingResultQueryDto {
  @IsOptional()
  @IsUUID()
  athleteProfileId?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_RANKING_PAGE_SIZE)
  limit?: number;

  /** The `id` of the last result of the previous page. */
  @IsOptional()
  @IsUUID()
  cursor?: string;
}

/** The path parameter of the update and delete routes. */
export class RankingResultParamsDto {
  @IsUUID()
  id!: string;
}
