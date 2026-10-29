import { createHmac, hkdfSync, randomInt, timingSafeEqual } from 'node:crypto';

/**
 * Single-use recovery codes for a second factor.
 *
 * Codes are shown once and stored only as HMAC-SHA256 hex. The HMAC key is a
 * sub-key derived from TOTP_ENC_KEY, so the raw key material is never used for
 * two purposes.
 */

/** Same alphabet as the TOTP secret: unambiguous when retyped by hand. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CODE_LENGTH = 10;
const GROUP_LENGTH = 5;
const MAX_COUNT = 100;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const NORMALIZED_PATTERN = /^[A-Z2-7]{10}$/;

const SUBKEY_INFO = 'kfa-recovery-code-v1';
const SUBKEY_BYTES = 32;

function deriveSubKey(key: Buffer): Buffer {
  // Empty salt: the info string is what keeps this use separate from AES-GCM.
  return Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), SUBKEY_INFO, SUBKEY_BYTES));
}

function digest(normalizedCode: string, key: Buffer): Buffer {
  return createHmac('sha256', deriveSubKey(key)).update(normalizedCode, 'utf8').digest();
}

function format(chars: string[]): string {
  return `${chars.slice(0, GROUP_LENGTH).join('')}-${chars.slice(GROUP_LENGTH).join('')}`;
}

/** `count` fresh codes, formatted `XXXXX-XXXXX` and guaranteed unique. */
export function generateRecoveryCodes(count = 10): string[] {
  if (!Number.isInteger(count) || count < 1 || count > MAX_COUNT) {
    throw new RangeError(`recovery code count must be between 1 and ${MAX_COUNT}`);
  }

  const codes = new Set<string>();

  while (codes.size < count) {
    const chars: string[] = [];

    for (let index = 0; index < CODE_LENGTH; index += 1) {
      // randomInt rejects out-of-range draws instead of folding them, so each
      // symbol stays equally likely.
      chars.push(BASE32_ALPHABET.charAt(randomInt(0, BASE32_ALPHABET.length)));
    }

    codes.add(format(chars));
  }

  return [...codes];
}

/** Uppercases and strips dashes/spaces; null unless exactly 10 base32 chars remain. */
export function normalizeRecoveryCode(input: unknown): string | null {
  if (typeof input !== 'string') return null;

  const normalized = input.replace(/[\s-]/g, '').toUpperCase();

  return NORMALIZED_PATTERN.test(normalized) ? normalized : null;
}

/** HMAC-SHA256 hex of the normalized code. Malformed codes are refused. */
export function hashRecoveryCode(code: string, key: Buffer): string {
  const normalizedCode = normalizeRecoveryCode(code);

  if (normalizedCode === null) throw new Error('invalid recovery code');

  return digest(normalizedCode, key).toString('hex');
}

/** Constant-time check of a typed-in code against a stored hash. */
export function recoveryCodeMatches(inputCode: unknown, storedHash: string, key: Buffer): boolean {
  const normalizedCode = normalizeRecoveryCode(inputCode);

  if (normalizedCode === null || !HASH_PATTERN.test(storedHash)) return false;

  const stored = Buffer.from(storedHash, 'hex');
  const expected = digest(normalizedCode, key);

  return stored.length === expected.length && timingSafeEqual(stored, expected);
}
