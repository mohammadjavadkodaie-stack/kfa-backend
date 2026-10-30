/**
 * Short-lived storage for the replacement secret of a TOTP rotation.
 *
 * The active credential stays untouched until the new one is confirmed, so the
 * pending ciphertext lives outside the credential row. Redis is used when it is
 * configured; the in-memory store keeps development and the API suites working
 * without one.
 */

export const TOTP_ROTATION_STORE = Symbol('TOTP_ROTATION_STORE');

/** Ten minutes: long enough to scan a QR code, short enough to stay useless. */
export const ROTATION_PENDING_TTL_SECONDS = 600;

const ROTATION_KEY_PREFIX = 'kfa:totp:rotate:';

export interface PendingRotation {
  /** Ciphertext of the replacement secret. The plaintext never leaves the call. */
  readonly secretEnc: string;
  /** Ciphertext of the active secret this replacement was bound to. */
  readonly expectedSecretEnc: string;
}

export interface TotpRotationStore {
  /** Overwrites an older pending replacement of the same user. */
  save(userId: string, pending: PendingRotation): Promise<void>;
  /** Null once expired or never started. */
  read(userId: string): Promise<PendingRotation | null>;
  clear(userId: string): Promise<void>;
}

/** The ioredis subset the store needs; the shared client provides all three. */
export interface TotpRotationRedisClient {
  set(key: string, value: string, mode: 'EX', ttlSeconds: number): Promise<'OK' | null>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
}

function keyFor(userId: string): string {
  return `${ROTATION_KEY_PREFIX}${userId}`;
}

function isPendingRotation(value: unknown): value is PendingRotation {
  if (typeof value !== 'object' || value === null) return false;

  const pending = value as Record<string, unknown>;

  return typeof pending.secretEnc === 'string' && typeof pending.expectedSecretEnc === 'string';
}

export class InMemoryTotpRotationStore implements TotpRotationStore {
  private readonly pending = new Map<
    string,
    { readonly value: PendingRotation; readonly expiresAt: number }
  >();

  constructor(private readonly clock: () => number = Date.now) {}

  async save(userId: string, pending: PendingRotation): Promise<void> {
    this.pending.set(userId, {
      value: { ...pending },
      expiresAt: this.clock() + ROTATION_PENDING_TTL_SECONDS * 1_000,
    });
  }

  async read(userId: string): Promise<PendingRotation | null> {
    const stored = this.pending.get(userId);

    if (stored === undefined) return null;

    if (stored.expiresAt <= this.clock()) {
      this.pending.delete(userId);

      return null;
    }

    return { ...stored.value };
  }

  async clear(userId: string): Promise<void> {
    this.pending.delete(userId);
  }
}

export class RedisTotpRotationStore implements TotpRotationStore {
  constructor(private readonly client: TotpRotationRedisClient) {}

  /** `SET EX` overwrites the older replacement and restarts its TTL. */
  async save(userId: string, pending: PendingRotation): Promise<void> {
    await this.client.set(
      keyFor(userId),
      JSON.stringify(pending),
      'EX',
      ROTATION_PENDING_TTL_SECONDS,
    );
  }

  async read(userId: string): Promise<PendingRotation | null> {
    const stored = await this.client.get(keyFor(userId));

    if (stored === null) return null;

    try {
      const parsed: unknown = JSON.parse(stored);

      if (isPendingRotation(parsed)) return parsed;
    } catch {
      // A torn or tampered value is treated like an expired one.
    }

    await this.clear(userId);

    return null;
  }

  async clear(userId: string): Promise<void> {
    await this.client.del(keyFor(userId));
  }
}
