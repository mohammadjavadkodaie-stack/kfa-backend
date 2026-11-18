/**
 * Single-use nonce store shared by every short-lived proof in the auth module.
 *
 * A proof token carries only an HMAC of its subject plus a `jti`; the subject
 * itself (an email address, a document id) is kept here until the token is
 * presented, so redeeming it is the only way to read the subject back - exactly
 * once, atomically.
 *
 * The store is deliberately subject-agnostic: the email identity proofs and the
 * single-use document view links both need it, and neither may depend on the
 * contracts of the other flow.
 */

/**
 * Redis key namespace. Kept as the historical `kfa:otp:proof:` prefix on
 * purpose: the namespace is shared, and renaming it would invalidate every
 * proof that is already in flight when a deployment rolls.
 */
export const PROOF_NONCE_KEY_PREFIX = 'kfa:otp:proof:';

/** DI token for the nonce store (absent when Redis is not configured). */
export const PROOF_NONCE_STORE = Symbol('PROOF_NONCE_STORE');

/** Stores the subject behind a nonce and hands it back exactly once. */
export interface ProofNonceStore {
  put(jti: string, subject: string, ttlSeconds: number): Promise<boolean>;
  /** Removes and returns the stored subject in one step (single use). */
  take(jti: string): Promise<string | null>;
  /**
   * Reads the stored subject WITHOUT spending the nonce.
   *
   * Optional: a store may support single use only. A flow that must validate
   * before committing (a password reset that refuses to burn the proof on a
   * weak password) checks for this method and fails closed when it is absent.
   */
  get?(jti: string): Promise<string | null>;
}

/** The ioredis subset the nonce store needs. */
export interface ProofRedisClient {
  set(key: string, value: string, mode: 'EX', ttlSeconds: number, nx: 'NX'): Promise<'OK' | null>;
  getdel(key: string): Promise<string | null>;
  /** Plain read, used only by the non-consuming `get` below. */
  get?(key: string): Promise<string | null>;
}

export class RedisProofNonceStore implements ProofNonceStore {
  constructor(private readonly client: ProofRedisClient) {}

  async put(jti: string, subject: string, ttlSeconds: number): Promise<boolean> {
    const reply = await this.client.set(
      `${PROOF_NONCE_KEY_PREFIX}${jti}`,
      subject,
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

  /** A plain read: the caller must still `take` before treating the proof as spent. */
  async get(jti: string): Promise<string | null> {
    const read = this.client.get?.bind(this.client);
    if (read === undefined) throw new Error('nonce store cannot peek');

    return read(`${PROOF_NONCE_KEY_PREFIX}${jti}`);
  }
}
