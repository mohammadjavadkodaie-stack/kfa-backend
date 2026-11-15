import { Transform, Type, type TransformFnParams } from 'class-transformer';
import { IsIn, IsInt, IsOptional, IsString, IsUUID, Length, Max, Min } from 'class-validator';
import type { ReviewStatus } from '../athlete/profile/athlete-profile.repository';

/**
 * The three states a submitted profile can sit in. DRAFT is deliberately absent:
 * a profile that was never submitted is not part of any queue and its owner is
 * still editing it, so a reviewer has no business listing it.
 */
export const REVIEW_QUEUE_STATUSES: readonly ReviewStatus[] = Object.freeze([
  'PENDING',
  'APPROVED',
  'REJECTED',
]);

/** A page of the queue, when the caller does not say how much it wants. */
export const DEFAULT_REVIEW_PAGE_SIZE = 20;

/** The hard cap: a reviewer reads the oldest first, so a huge page buys nothing. */
export const MAX_REVIEW_PAGE_SIZE = 50;

/** Matches `rejection_reason` `VarChar(500)`; the column is the real limit. */
export const MAX_REJECTION_REASON_LENGTH = 500;

/** Trims before the length rules run, so a reason of spaces is never a reason. */
const trimmed = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string' ? value.trim() : value;

/**
 * `GET /staff/reviews?status=&limit=&cursor=`.
 *
 * Everything is optional and every field is declared, so the global pipe turns a
 * misspelled or unknown parameter into a generic 400 instead of silently
 * ignoring it - a filter nobody applied is a wrong list.
 */
export class ReviewQueueQueryDto {
  @IsOptional()
  @IsIn(REVIEW_QUEUE_STATUSES)
  status?: ReviewStatus;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_REVIEW_PAGE_SIZE)
  limit?: number;

  /** The `profileId` of the last row of the previous page. */
  @IsOptional()
  @IsUUID()
  cursor?: string;
}

/**
 * The path parameter of the three single-profile routes. Any versioned UUID is
 * accepted, so a generator change cannot lock existing ids out.
 */
export class ReviewProfileParamsDto {
  @IsUUID()
  profileId!: string;
}

/**
 * The only thing a rejection may carry. There is no reviewer, no status and no
 * timestamp here: those come from the token and the clock, so a request cannot
 * name the decision it wants recorded.
 */
export class RejectReviewDto {
  @Transform(trimmed)
  @IsString()
  @Length(1, MAX_REJECTION_REASON_LENGTH)
  reason!: string;
}

/** Maps the query to the input the service takes, without the DTO's optionals. */
export function toQueueQuery(query: ReviewQueueQueryDto): {
  status?: ReviewStatus;
  limit?: number;
  cursor?: string;
} {
  return { status: query.status, limit: query.limit, cursor: query.cursor };
}
