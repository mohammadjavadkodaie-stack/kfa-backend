import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { normalizePassword, PASSWORD_MAX_LENGTH } from './password.policy';

/** Stored-format version. Bumped when the parameters (not the algorithm) change. */
export const SCRYPT_VERSION = 'v1';
const SCRYPT_SCHEME = 'scrypt';

/** N=2^16 / r=8 / p=2 is ~64 MiB and ~0.3 s of memory-hard work per hash on a laptop CPU. */
export const SCRYPT_N = 65_536;
export const SCRYPT_R = 8;
export const SCRYPT_P = 2;
export const SCRYPT_KEY_LENGTH = 32;
export const SCRYPT_SALT_LENGTH = 16;
/** Caps the memory ceiling so a hostile stored string cannot ask for gigabytes. */
export const SCRYPT_MAX_MEM = 256 * 1024 * 1024;

/** scrypt$v1$65536,8,2$<salt>$<hash> is ~86 characters; the DB CHECK allows 20..512. */
export const PASSWORD_HASH_MAX_LENGTH = 200;

/** Scrypt is memory-hard by design: three at a time keeps ~200 MiB of peak RSS. */
export const MAX_CONCURRENT_HASHES = 3;
/**
 * A bounded queue, not an unbounded one: under a login flood we would rather shed load with a
 * 503 than let thousands of pending scrypts exhaust the heap.
 */
export const MAX_HASH_QUEUE = 50;

/** Bounds applied to parameters read back from the database before any work is done. */
const MIN_STORED_N = 2 ** 14;
const MAX_STORED_N = 2 ** 20;
const MIN_STORED_P = 1;
const MAX_STORED_P = 4;
const STORED_R = 8;

const PARAMS_PATTERN = /^(\d{1,8}),(\d{1,4}),(\d{1,4})$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;

/** Capacity error: the future login path surfaces it as 503, never as a credential failure. */
export class PasswordBusyError extends ServiceUnavailableException {
  constructor() {
    super('Password hashing capacity is exhausted');
  }
}

/** Raised before hashing when the input exceeds PASSWORD_MAX_LENGTH code points. */
export class PasswordTooLongError extends Error {
  constructor() {
    super('Password exceeds the maximum supported length');
    this.name = 'PasswordTooLongError';
  }
}

interface ScryptParams {
  readonly n: number;
  readonly r: number;
  readonly p: number;
}

interface ParsedHash extends ScryptParams {
  readonly salt: Buffer;
  readonly key: Buffer;
}

function isPowerOfTwo(value: number): boolean {
  return value > 0 && (value & (value - 1)) === 0;
}

function decodeSegment(segment: string, expectedLength: number): Buffer | null {
  if (!BASE64URL_PATTERN.test(segment)) return null;
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.length !== expectedLength) return null;
  // Buffer.from is lenient about padding and trailing junk; re-encoding is the strict check.
  return decoded.toString('base64url') === segment ? decoded : null;
}

function parseStored(stored: unknown): ParsedHash | null {
  if (typeof stored !== 'string') return null;
  if (stored.length === 0 || stored.length > PASSWORD_HASH_MAX_LENGTH) return null;

  const parts = stored.split('$');
  if (parts.length !== 5) return null;
  const [scheme, version, params, saltSegment, keySegment] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];
  if (scheme !== SCRYPT_SCHEME || version !== SCRYPT_VERSION) return null;

  const match = PARAMS_PATTERN.exec(params);
  if (match === null) return null;
  const n = Number(match[1]);
  const r = Number(match[2]);
  const p = Number(match[3]);
  if (!isPowerOfTwo(n) || n < MIN_STORED_N || n > MAX_STORED_N) return null;
  if (r !== STORED_R) return null;
  if (!Number.isInteger(p) || p < MIN_STORED_P || p > MAX_STORED_P) return null;

  const salt = decodeSegment(saltSegment, SCRYPT_SALT_LENGTH);
  const key = decodeSegment(keySegment, SCRYPT_KEY_LENGTH);
  if (salt === null || key === null) return null;

  return { n, r, p, salt, key };
}

function deriveKey(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      SCRYPT_KEY_LENGTH,
      { N: params.n, r: params.r, p: params.p, maxmem: SCRYPT_MAX_MEM },
      (error, derived) => (error ? reject(error) : resolve(derived)),
    );
  });
}

/**
 * Bounded concurrency gate around scrypt. At most `limit` derivations run at once; at most
 * `maxQueue` callers wait; everyone beyond that is rejected immediately instead of piling up.
 */
export class ScryptSemaphore {
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(
    private readonly limit: number = MAX_CONCURRENT_HASHES,
    private readonly maxQueue: number = MAX_HASH_QUEUE,
  ) {}

  get inFlight(): number {
    return this.active;
  }

  get queued(): number {
    return this.waiting.length;
  }

  async run<T>(work: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await work();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve();
    }
    if (this.waiting.length >= this.maxQueue) return Promise.reject(new PasswordBusyError());
    return new Promise<void>((resolve) => {
      this.waiting.push(resolve);
    });
  }

  private release(): void {
    const next = this.waiting.shift();
    if (next === undefined) {
      this.active -= 1;
      return;
    }
    // Hand the slot over directly: `active` does not change, so no caller can slip in between.
    next();
  }
}

@Injectable()
export class PasswordService {
  private readonly semaphore = new ScryptSemaphore(MAX_CONCURRENT_HASHES, MAX_HASH_QUEUE);
  private dummy: Promise<string> | null = null;

  async hash(password: string): Promise<string> {
    if (typeof password !== 'string') throw new TypeError('password must be a string');
    const normalized = normalizePassword(password);
    // Refuse oversized input before it reaches scrypt: the cost is in the key derivation, so
    // this length check is the cheap half of the hashing-DoS guard.
    if (Array.from(normalized).length > PASSWORD_MAX_LENGTH) throw new PasswordTooLongError();

    const salt = randomBytes(SCRYPT_SALT_LENGTH);
    const key = await this.semaphore.run(() =>
      deriveKey(normalized, salt, { n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }),
    );
    return [
      SCRYPT_SCHEME,
      SCRYPT_VERSION,
      `${SCRYPT_N},${SCRYPT_R},${SCRYPT_P}`,
      salt.toString('base64url'),
      key.toString('base64url'),
    ].join('$');
  }

  /**
   * Never throws for malformed input: a corrupted or foreign hash is simply "not a match", which
   * keeps the caller's error path indistinguishable from a wrong password. PasswordBusyError is
   * the one exception, because shedding load is a capacity decision rather than a verdict.
   */
  async verify(password: unknown, stored: unknown): Promise<boolean> {
    if (typeof password !== 'string') return false;
    const parsed = parseStored(stored);
    if (parsed === null) return false;

    let normalized: string;
    try {
      normalized = normalizePassword(password);
    } catch {
      return false;
    }
    // No stored hash can exist for a longer password: hash() refuses to create one.
    if (Array.from(normalized).length > PASSWORD_MAX_LENGTH) return false;

    let derived: Buffer;
    try {
      derived = await this.semaphore.run(() => deriveKey(normalized, parsed.salt, parsed));
    } catch (error) {
      if (error instanceof PasswordBusyError) throw error;
      return false;
    }
    // Lengths always match (the key length is fixed), but timingSafeEqual demands it explicitly.
    return derived.length === parsed.key.length && timingSafeEqual(derived, parsed.key);
  }

  needsRehash(stored: unknown): boolean {
    const parsed = parseStored(stored);
    if (parsed === null) return true;
    return parsed.n !== SCRYPT_N || parsed.r !== SCRYPT_R || parsed.p !== SCRYPT_P;
  }

  /** Burns one derivation so an unknown-email login costs the same as a known one. Always false. */
  async verifyDummy(password: unknown): Promise<boolean> {
    let stored: string;
    try {
      stored = await this.dummyHash();
    } catch (error) {
      if (error instanceof PasswordBusyError) throw error;
      return false;
    }

    try {
      await this.verify(password, stored);
    } catch (error) {
      if (error instanceof PasswordBusyError) throw error;
    }
    return false;
  }

  private dummyHash(): Promise<string> {
    if (this.dummy === null) {
      // A random 32-byte secret: nothing a caller can supply will ever match it.
      const secret = randomBytes(32).toString('base64url');
      this.dummy = this.hash(secret).catch((error: unknown) => {
        this.dummy = null;
        throw error;
      });
    }
    return this.dummy;
  }
}
