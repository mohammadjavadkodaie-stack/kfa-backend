import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * The signed, single-use link token that opens one identity document for one
 * viewer.
 *
 * The payload carries identifiers and a nonce, never the document: no object
 * key, no owner id, no file name, no content type and no bytes. The signature
 * covers every claim, so a token minted for one document cannot be re-pointed at
 * another one, and the one-time half of the guarantee lives in a store next to
 * the nonce instead of inside the token.
 *
 * Expiry is a signed claim as well: a token is refused without touching the
 * store, so a stale link never burns a nonce the live flow still needs.
 */

/** How long an issued link stays redeemable: one quick click, no longer. */
export const VIEW_LINK_TTL_SECONDS = 60;

/**
 * How long the nonce is remembered. Longer than the token itself, so a link can
 * never outlive its nonce, with room for clock skew between instances.
 */
export const VIEW_LINK_CONSUMPTION_TTL_SECONDS = 2 * VIEW_LINK_TTL_SECONDS;

/** Defensive bound: a valid link token is a few hundred characters. */
export const VIEW_TOKEN_MAX_LENGTH = 2048;

const SIGNATURE_BYTES = 32;
/** 16 random bytes, base64url. */
const JTI_BYTES = 16;
const JTI_PATTERN = /^[A-Za-z0-9_-]{22}$/;
/** Base64url only: anything else is refused before it is parsed. */
const SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN_VERSION = 1;

/** What a link token asserts. Every field is signed. */
export interface ViewTokenPayload {
  readonly v: typeof TOKEN_VERSION;
  /** The nonce that has to be spent for the link to be used at all. */
  readonly jti: string;
  readonly documentId: string;
  /** The viewer, never the owner: the owner id is not part of the link. */
  readonly viewerUserId: string;
  /** True only when the issuer decided the staff basis for this link. */
  readonly staff: boolean;
  /** Expiry, seconds since the epoch. */
  readonly exp: number;
}

/** A freshly minted token and the nonce the caller has to remember. */
export interface IssuedViewToken {
  readonly token: string;
  readonly jti: string;
  readonly exp: number;
}

export interface IssueViewTokenInput {
  readonly secret: string;
  readonly documentId: string;
  readonly viewerUserId: string;
  readonly staff: boolean;
  /** Milliseconds since the epoch; injectable so the specs own the clock. */
  readonly nowMs: number;
}

export interface VerifyViewTokenInput {
  readonly secret: string;
  readonly token: unknown;
  readonly nowMs: number;
}

function sign(secret: string, payloadSegment: string): Buffer {
  return createHmac('sha256', secret).update(payloadSegment, 'utf8').digest();
}

/** Shape check after the signature verified: no claim is trusted on its own. */
function isViewTokenPayload(value: unknown): value is ViewTokenPayload {
  if (typeof value !== 'object' || value === null) return false;

  const payload = value as Record<string, unknown>;

  return (
    payload.v === TOKEN_VERSION &&
    typeof payload.jti === 'string' &&
    JTI_PATTERN.test(payload.jti) &&
    typeof payload.documentId === 'string' &&
    UUID_PATTERN.test(payload.documentId) &&
    typeof payload.viewerUserId === 'string' &&
    UUID_PATTERN.test(payload.viewerUserId) &&
    typeof payload.staff === 'boolean' &&
    typeof payload.exp === 'number' &&
    Number.isInteger(payload.exp)
  );
}

/**
 * Mints one link token and returns it together with the nonce and the expiry it
 * carries, so the caller can remember the nonce and describe the lifetime
 * without parsing its own token back.
 */
export function issueViewToken(input: IssueViewTokenInput): IssuedViewToken {
  const jti = randomBytes(JTI_BYTES).toString('base64url');
  const exp = Math.floor(input.nowMs / 1_000) + VIEW_LINK_TTL_SECONDS;
  const payload: ViewTokenPayload = {
    v: TOKEN_VERSION,
    jti,
    documentId: input.documentId,
    viewerUserId: input.viewerUserId,
    staff: input.staff,
    exp,
  };
  const payloadSegment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = sign(input.secret, payloadSegment).toString('base64url');

  return { token: `${payloadSegment}.${signature}`, jti, exp };
}

/**
 * Checks signature, shape and expiry, in that order, and returns the claims or
 * null. Every failure answers null with no detail: a caller must not be able to
 * tell a tampered token from an expired or a malformed one.
 */
export function verifyViewToken(input: VerifyViewTokenInput): ViewTokenPayload | null {
  const { token, secret, nowMs } = input;

  if (typeof token !== 'string' || token.length === 0 || token.length > VIEW_TOKEN_MAX_LENGTH) {
    return null;
  }

  const parts = token.split('.');

  if (parts.length !== 2) return null;

  const [payloadSegment, signatureSegment] = parts as [string, string];

  if (!SEGMENT_PATTERN.test(payloadSegment) || !SEGMENT_PATTERN.test(signatureSegment)) {
    return null;
  }

  const signature = Buffer.from(signatureSegment, 'base64url');
  const expected = sign(secret, payloadSegment);

  if (signature.length !== SIGNATURE_BYTES || !timingSafeEqual(signature, expected)) {
    return null;
  }

  let decoded: unknown;

  try {
    decoded = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  if (!isViewTokenPayload(decoded)) return null;

  // Expired means "not after now": the link is dead exactly when it says so.
  if (decoded.exp <= Math.floor(nowMs / 1_000)) return null;

  return decoded;
}
