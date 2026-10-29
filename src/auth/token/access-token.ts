import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * HS256 access tokens, built by hand on `node:crypto`.
 *
 * The header is data, never instructions: the algorithm is fixed to HS256 and a
 * token claiming anything else (`none`, `RS256`, ...) is rejected before the
 * signature is even looked at. The signature covers the exact encoded segments,
 * so re-encoding the payload cannot produce a token that verifies.
 */

/** Fixed algorithm; header `alg` is compared, never used to pick an algorithm. */
export const ACCESS_TOKEN_ALGORITHM = 'HS256';
export const ACCESS_TOKEN_ISSUER = 'kfa-api';
export const ACCESS_TOKEN_AUDIENCE = 'kfa-client';

/** Defensive bound: a real token is ~300 characters. */
const MAX_TOKEN_LENGTH = 4096;
const SIGNATURE_LENGTH = 32;
const SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface AccessTokenClaims {
  /** User id. */
  readonly sub: string;
  /** Session id: the guard checks it is still alive. */
  readonly sid: string;
  readonly iat: number;
  readonly exp: number;
  readonly iss: string;
  readonly aud: string;
}

export interface SignAccessTokenInput {
  readonly secret: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly issuedAtSeconds: number;
  readonly ttlSeconds: number;
}

export interface VerifyAccessTokenInput {
  readonly secret: string;
  readonly token: unknown;
  /** Injectable clock; seconds since the epoch. */
  readonly nowSeconds: number;
}

function encodeSegment(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function sign(secret: string, signingInput: string): Buffer {
  return createHmac('sha256', secret).update(signingInput, 'utf8').digest();
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

    return typeof decoded === 'object' && decoded !== null
      ? (decoded as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function isClaims(
  value: Record<string, unknown>,
): value is Record<string, unknown> & AccessTokenClaims {
  return (
    typeof value.sub === 'string' &&
    UUID_PATTERN.test(value.sub) &&
    typeof value.sid === 'string' &&
    UUID_PATTERN.test(value.sid) &&
    typeof value.iat === 'number' &&
    Number.isInteger(value.iat) &&
    typeof value.exp === 'number' &&
    Number.isInteger(value.exp) &&
    typeof value.iss === 'string' &&
    typeof value.aud === 'string'
  );
}

export function signAccessToken(input: SignAccessTokenInput): string {
  const header = encodeSegment({ alg: ACCESS_TOKEN_ALGORITHM, typ: 'JWT' });
  const claims: AccessTokenClaims = {
    sub: input.userId,
    sid: input.sessionId,
    iat: input.issuedAtSeconds,
    exp: input.issuedAtSeconds + input.ttlSeconds,
    iss: ACCESS_TOKEN_ISSUER,
    aud: ACCESS_TOKEN_AUDIENCE,
  };
  const signingInput = `${header}.${encodeSegment(claims)}`;

  return `${signingInput}.${sign(input.secret, signingInput).toString('base64url')}`;
}

/** Returns the claims of a valid, unexpired token, or null. Never throws. */
export function verifyAccessToken(input: VerifyAccessTokenInput): AccessTokenClaims | null {
  const { token, secret } = input;

  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  if (
    !SEGMENT_PATTERN.test(headerSegment) ||
    !SEGMENT_PATTERN.test(payloadSegment) ||
    !SEGMENT_PATTERN.test(signatureSegment)
  ) {
    return null;
  }

  const signature = Buffer.from(signatureSegment, 'base64url');
  const expected = sign(secret, `${headerSegment}.${payloadSegment}`);

  // Length first: timingSafeEqual throws on a mismatch instead of returning false.
  if (signature.length !== SIGNATURE_LENGTH || !timingSafeEqual(signature, expected)) {
    return null;
  }

  const header = decodeSegment(headerSegment);
  if (header === null || header.alg !== ACCESS_TOKEN_ALGORITHM) return null;

  const claims = decodeSegment(payloadSegment);
  if (claims === null || !isClaims(claims)) return null;

  if (claims.iss !== ACCESS_TOKEN_ISSUER || claims.aud !== ACCESS_TOKEN_AUDIENCE) return null;
  if (claims.exp <= input.nowSeconds) return null;

  return claims;
}
