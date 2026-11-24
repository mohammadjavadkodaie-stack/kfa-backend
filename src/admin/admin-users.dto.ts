import { BadRequestException } from '@nestjs/common';
import { Transform, Type, type TransformFnParams } from 'class-transformer';
import { IsEmail, IsIn, IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { z } from 'zod';
import { normalizeEmail } from '../auth/email/email';
import { ALL_ROLES, type Role } from '../auth/roles';

/** Page size when the request names none. */
export const DEFAULT_ADMIN_USERS_PAGE_SIZE = 20;
/** Largest page one request may pull: the UI pages, it does not export. */
export const MAX_ADMIN_USERS_PAGE_SIZE = 100;

/** The only spellings of the blocked filter a request may use. */
export const ADMIN_USERS_BLOCKED_VALUES = ['true', 'false'] as const;

/** The shortest reason a moderation may carry; anything shorter is no record. */
export const MIN_MODERATION_REASON_LENGTH = 5;
/** The longest one the trail will hold. */
export const MAX_MODERATION_REASON_LENGTH = 500;

/** Control characters (including tab and newline) and the two tag brackets. */
const NOT_PLAIN_TEXT = /[\u0000-\u001f\u007f<>]/;

/**
 * The body of `POST /admin/users/:id/block` and `.../unblock`.
 *
 * A staff moderation without a recorded reason is not a moderation, so the
 * body is required and a `strictObject`: an undeclared key - `status`, `id`,
 * `actorId` - is the generic 400 instead of being silently dropped. The reason
 * is trimmed, bounded and plain text only: control characters and angle
 * brackets are refused, because it is written to the audit trail and must not
 * carry markup or a payload. It is never echoed in a response or a log.
 */
export const moderationReasonSchema = z.strictObject({
  reason: z
    .string()
    .trim()
    .min(MIN_MODERATION_REASON_LENGTH)
    .max(MAX_MODERATION_REASON_LENGTH)
    .refine((value) => !NOT_PLAIN_TEXT.test(value)),
});

export type ModerationReasonWire = z.infer<typeof moderationReasonSchema>;

/** The wire gate: a body outside the schema is the same generic 400 as any DTO. */
export function parseModerationReason(body: unknown): ModerationReasonWire {
  const parsed = moderationReasonSchema.safeParse(body);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * The address filter is folded to its stored spelling on the way in, so a
 * search hits the same column the auth flow writes. A value that does not
 * survive normalisation keeps its original spelling here and is refused by
 * `@IsEmail` right after.
 */
const normalizeEmailFilter = ({ value }: TransformFnParams): unknown => {
  if (typeof value !== 'string') return value;

  return normalizeEmail(value) ?? value;
};

/**
 * Everything `GET /admin/users` accepts, all of it optional. The global
 * whitelist pipe drops keys this class does not name, and a wrong type on any
 * named key is a 400 before the service runs.
 */
export class AdminUsersQueryDto {
  @IsOptional()
  @IsIn(ALL_ROLES)
  role?: Role;

  /** Kept as its query-string spelling here; the mapper turns it into a boolean. */
  @IsOptional()
  @IsIn(ADMIN_USERS_BLOCKED_VALUES)
  blocked?: 'true' | 'false';

  @IsOptional()
  @IsString()
  @MaxLength(254)
  @Transform(normalizeEmailFilter)
  @IsEmail()
  email?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_ADMIN_USERS_PAGE_SIZE)
  pageSize?: number;
}

/** The filter the service hands to the repository, with defaults applied. */
export interface AdminUsersFilter {
  readonly page: number;
  readonly pageSize: number;
  readonly role?: Role;
  readonly blocked?: boolean;
  readonly email?: string;
}

/**
 * Query DTO to repository filter. Validation already ran; this only applies
 * the defaults (`page` 1, `pageSize` 20) and the boolean spelling.
 */
export function toAdminUsersFilter(query: AdminUsersQueryDto): AdminUsersFilter {
  return {
    page: query.page ?? 1,
    pageSize: query.pageSize ?? DEFAULT_ADMIN_USERS_PAGE_SIZE,
    ...(query.role === undefined ? {} : { role: query.role }),
    ...(query.blocked === undefined ? {} : { blocked: query.blocked === 'true' }),
    ...(query.email === undefined ? {} : { email: query.email }),
  };
}
