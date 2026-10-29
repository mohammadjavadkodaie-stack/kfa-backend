import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';

/**
 * Short-lived proof that a phone number passed the OTP check.
 *
 * The token never carries the raw phone: the payload holds an HMAC of the
 * phone, a nonce (`jti`), the action it was issued for (`purpose`) and an
 * expiry. The phone itself is stored in Redis next to the nonce, so consuming
 * the token is the only way to read it back - exactly once, atomically.
 *
 * The purpose is a signed claim, so a proof minted for one action cannot be
 * replayed against another one (a login proof at the register endpoint).
 */

export const PROOF_TTL_SECONDS = 600;
export const PROOF_NONCE_KEY_PREFIX = 'kfa:otp:proof:';

/**
 * The only actions a proof may authorize. Closed set: the value always comes
 * from this list, never from caller input that has not been narrowed to it.
 */
export const PROOF_PURPOSES = [
  'register',
  'login',
  'phone_change_new',
  'phone_change_old',
] as const;

export type ProofPurpose = (typeof PROOF_PURPOSES)[number];

const PROOF_PURPOSE_SET: ReadonlySet<string> = new Set(PROOF_PURPOSES);

/** Narrows an untrusted value to the closed set of proof purposes. */
export function isProofPurpose(value: unknown): value is ProofPurpose {
  return typeof value === 'string' && PROOF_PURPOSE_SET.has(value);
}

/** Defensive bound: a valid token is ~200 characters. */
const MAX_TOKEN_LENGTH = 2048;
const SIGNATURE_LENGTH = 32;
const PHONE_HASH_PATTERN = /^[0-9a-f]{64}$/;
const JTI_PATTERN = /^[0-9a-f-]{36}$/;

/** DI token for the nonce store (absent when Redis is not configured). */
export const PROOF_NONCE_STORE = Symbol('PROOF_NONCE_STORE');

/** Stores the phone behind a nonce and hands it back exactly once. */
export interface ProofNonceStore {
  put(jti: string, phoneE164: string, ttlSeconds: number): Promise<boolean>;
  /** Removes and returns the stored phone in one step (single use). */
  take(jti: string): Promise<string | null>;
}

/** The ioredis subset the nonce store needs. */
export interface ProofRedisClient {
  set(key: string, value: string, mode: 'EX', ttlSeconds: number, nx: 'NX'): Promise<'OK' | null>;
  getdel(key: string): Promise<string | null>;
}

export class RedisProofNonceStore implements ProofNonceStore {
  constructor(private readonly client: ProofRedisClient) {}

  async put(jti: string, phoneE164: string, ttlSeconds: number): Promise<boolean> {
    const reply = await this.client.set(
      `${PROOF_NONCE_KEY_PREFIX}${jti}`,
      phoneE164,
      'EX',
      ttlSeconds,
      'NX',
    );

    return reply === 'OK';
  }

  async take(jti: string): Promise<string | null> {
    // GETDEL keeps "read" and "delete" atomic, so a replay cannot win a race.
    return this.client.getdel(`${PROOF_NONCE_KEY_PREFIX}${jti}`);
  }
}

interface ProofPayload {
  readonly v: 2;
  readonly phoneHash: string;
  readonly jti: string;
  readonly purpose: ProofPurpose;
  readonly exp: number;
}

function base64UrlEncode(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

function phoneDigest(secret: string, phoneE164: string): string {
  return createHmac('sha256', secret).update(`phone:${phoneE164}`, 'utf8').digest('hex');
}

function sign(secret: string, payloadSegment: string): Buffer {
  return createHmac('sha256', secret).update(payloadSegment, 'utf8').digest();
}

function isProofPayload(value: unknown): value is ProofPayload {
  if (typeof value !== 'object' || value === null) return false;

  const payload = value as Record<string, unknown>;

  return (
    // Version 1 tokens carry no purpose and are refused from here on.
    payload.v === 2 &&
    isProofPurpose(payload.purpose) &&
    typeof payload.phoneHash === 'string' &&
    PHONE_HASH_PATTERN.test(payload.phoneHash) &&
    typeof payload.jti === 'string' &&
    JTI_PATTERN.test(payload.jti) &&
    typeof payload.exp === 'number' &&
    Number.isInteger(payload.exp)
  );
}

/** Length-checked, constant-time comparison of two UTF-8 strings. */
function equalInConstantTime(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');

  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function unavailable(): ServiceUnavailableException {
  // Generic on purpose: callers never learn why the proof store failed.
  return new ServiceUnavailableException();
}

@Injectable()
export class ProofTokenService {
  private readonly secret: string | undefined;

  constructor(
    @Inject(ENV) env: Pick<Env, 'OTP_PROOF_SECRET'>,
    @Inject(PROOF_NONCE_STORE) private readonly store: ProofNonceStore | null,
  ) {
    this.secret = env.OTP_PROOF_SECRET;
  }

  /** Issues a proof for a normalized phone and purpose, remembering it until it expires. */
  async issue(
    phoneE164: string,
    purpose: ProofPurpose,
    nowMs: number = Date.now(),
  ): Promise<string> {
    const secret = this.secret;
    const store = this.store;

    if (secret === undefined || store === null) {
      throw unavailable();
    }

    const jti = randomUUID();
    const payload: ProofPayload = {
      v: 2,
      phoneHash: phoneDigest(secret, phoneE164),
      jti,
      purpose,
      exp: Math.floor(nowMs / 1_000) + PROOF_TTL_SECONDS,
    };

    try {
      if (!(await store.put(jti, phoneE164, PROOF_TTL_SECONDS))) {
        throw new Error('proof nonce collision');
      }
    } catch {
      throw unavailable();
    }

    const payloadSegment = base64UrlEncode(JSON.stringify(payload));
    const signature = sign(secret, payloadSegment).toString('base64url');

    return `${payloadSegment}.${signature}`;
  }

  /**
   * Returns the normalized phone behind a valid proof issued for
   * `expectedPurpose`, or null. The nonce is consumed, so the same token can
   * never succeed twice.
   */
  async verifyAndConsumeProof(
    token: unknown,
    expectedPurpose: ProofPurpose,
    nowMs: number = Date.now(),
  ): Promise<string | null> {
    const secret = this.secret;
    const store = this.store;

    if (secret === undefined || store === null) {
      throw unavailable();
    }

    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      return null;
    }

    const parts = token.split('.');
    if (parts.length !== 2) return null;

    const [payloadSegment, signatureSegment] = parts as [string, string];
    const signature = Buffer.from(signatureSegment, 'base64url');
    const expected = sign(secret, payloadSegment);

    if (signature.length !== SIGNATURE_LENGTH || !timingSafeEqual(signature, expected)) {
      return null;
    }

    let decoded: unknown;

    try {
      decoded = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
    } catch {
      return null;
    }

    if (!isProofPayload(decoded)) return null;

    // A stale token is refused without touching the store; its nonce simply expires.
    if (decoded.exp <= Math.floor(nowMs / 1_000)) return null;

    // Also stateless: a wrong-purpose attempt must not burn the nonce the
    // legitimate flow still needs, so the purpose is checked before GETDEL.
    if (!equalInConstantTime(decoded.purpose, expectedPurpose)) return null;

    let phoneE164: string | null;

    try {
      phoneE164 = await store.take(decoded.jti);
    } catch {
      throw unavailable();
    }

    if (
      phoneE164 === null ||
      !equalInConstantTime(phoneDigest(secret, phoneE164), decoded.phoneHash)
    ) {
      return null;
    }

    return phoneE164;
  }
}
