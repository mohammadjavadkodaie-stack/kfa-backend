import { Transform, Type, type TransformFnParams } from 'class-transformer';
import { IsEmail, IsIn, IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { normalizeEmail } from '../auth/email/email';
import { ALL_ROLES, type Role } from '../auth/roles';

/** Page size when the request names none. */
export const DEFAULT_ADMIN_USERS_PAGE_SIZE = 20;
/** Largest page one request may pull: the UI pages, it does not export. */
export const MAX_ADMIN_USERS_PAGE_SIZE = 100;

/** The only spellings of the blocked filter a request may use. */
export const ADMIN_USERS_BLOCKED_VALUES = ['true', 'false'] as const;

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
