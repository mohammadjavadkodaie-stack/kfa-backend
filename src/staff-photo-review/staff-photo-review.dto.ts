import { BadRequestException } from '@nestjs/common';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { z } from 'zod';

/**
 * The queue reads PENDING photos only, so there is no status filter and no
 * unknown parameter to ignore: a caller states a page size and a cursor, and
 * nothing else.
 */

/** A page of the queue, when the caller does not say how much it wants. */
export const DEFAULT_PHOTO_REVIEW_PAGE_SIZE = 20;

/** The hard cap: the oldest first, so a huge page buys a reviewer nothing. */
export const MAX_PHOTO_REVIEW_PAGE_SIZE = 50;

/**
 * Longest rejection reason a reviewer may send. It is stored in the audit
 * metadata only, so this is a log-field cap rather than a column limit.
 */
export const MAX_PHOTO_REJECTION_REASON_LENGTH = 200;

/**
 * `GET /staff/photo-reviews?limit=&cursor=`.
 *
 * Both fields are declared, so the global pipe turns a misspelled or unknown
 * parameter into a generic 400 instead of silently ignoring it.
 */
export class PhotoReviewQueueQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_PHOTO_REVIEW_PAGE_SIZE)
  limit?: number;

  /** The `id` of the last photo of the previous page. */
  @IsOptional()
  @IsUUID()
  cursor?: string;
}

/** The path parameter of the two decision routes. */
export class PhotoReviewParamsDto {
  @IsUUID()
  photoId!: string;
}

/**
 * The only thing a rejection may carry: the reviewer's optional words. There is
 * no reviewer, no status and no timestamp here - those come from the token and
 * the clock - and the text is trimmed, so a reason of spaces is no reason.
 * zod is the whole gate, so unknown keys are refused rather than ignored.
 */
export const rejectPhotoSchema = z.strictObject({
  reason: z
    .string()
    .max(MAX_PHOTO_REJECTION_REASON_LENGTH)
    .optional()
    .transform((value) => {
      if (value === undefined) return null;

      const text = value.trim();

      return text.length === 0 ? null : text;
    }),
});

export type RejectPhotoInput = z.infer<typeof rejectPhotoSchema>;

/** The wire gate: a body outside the schema is the generic 400. */
export function parseRejectPhoto(body: unknown): RejectPhotoInput {
  const parsed = rejectPhotoSchema.safeParse(body ?? {});

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}
