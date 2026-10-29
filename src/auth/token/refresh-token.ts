import { createHash, randomBytes } from 'node:crypto';

/**
 * Refresh tokens and their cookie.
 *
 * The token is an opaque 256-bit random value: it carries no claims, so it can
 * only be checked against the database. That is deliberate - a token must be
 * revocable the moment it leaks, and the database only ever holds its SHA-256.
 */

export const REFRESH_TOKEN_BYTES = 32;

/**
 * `__Host-` forces the browser to keep the cookie on this exact origin: Secure,
 * Path=/ and no Domain attribute. A sibling subdomain cannot overwrite it.
 */
export const REFRESH_COOKIE_NAME = '__Host-kfa_rt';
export const REFRESH_COOKIE_PATH = '/';

/** A cookie value longer than this is not ours; refuse before hashing it. */
const MAX_COOKIE_HEADER_LENGTH = 4096;
/** 32 random bytes in base64url are always 43 characters. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface RefreshCookieOptions {
  readonly httpOnly: true;
  readonly secure: true;
  readonly sameSite: 'strict';
  readonly path: string;
  /** Express expects milliseconds. */
  readonly maxAge: number;
}

export function generateRefreshToken(): string {
  return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
}

/** The only form a refresh token is ever persisted in. */
export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function isRefreshTokenShaped(token: unknown): token is string {
  return typeof token === 'string' && TOKEN_PATTERN.test(token);
}

/**
 * Hand-written cookie lookup: cookie-parser is not a dependency, and the only
 * cookie this service reads is its own refresh token.
 */
export function readCookie(header: string | undefined, name: string): string | null {
  if (
    typeof header !== 'string' ||
    header.length === 0 ||
    header.length > MAX_COOKIE_HEADER_LENGTH
  ) {
    return null;
  }

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;

    if (part.slice(0, separator).trim() !== name) continue;

    const value = part.slice(separator + 1).trim();

    return value.length > 0 && value.length <= 256 ? value : null;
  }

  return null;
}

/** min(refresh TTL, what is left of the absolute session) in whole seconds. */
export function refreshCookieLifetimeSeconds(
  refreshTtlSeconds: number,
  sessionExpiresAt: Date,
  now: Date,
): number {
  const sessionRemaining = Math.ceil((sessionExpiresAt.getTime() - now.getTime()) / 1_000);

  return Math.max(0, Math.min(refreshTtlSeconds, sessionRemaining));
}

export function refreshCookieOptions(maxAgeSeconds: number): RefreshCookieOptions {
  return {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: REFRESH_COOKIE_PATH,
    maxAge: maxAgeSeconds * 1_000,
  };
}

/** Clearing needs the same attributes, otherwise the browser keeps the cookie. */
export function clearRefreshCookieOptions(): Omit<RefreshCookieOptions, 'maxAge'> {
  return {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: REFRESH_COOKIE_PATH,
  };
}
