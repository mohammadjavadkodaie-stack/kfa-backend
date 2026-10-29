import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * TOTP (RFC 6238) built on HOTP (RFC 4226). Pure functions only: no storage,
 * no clock access - every caller passes the time it wants to use.
 */

/** RFC 4648 base32 alphabet, in the canonical order. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** 160 random bits, the RFC 4226 recommendation for an HMAC-SHA1 secret. */
const SECRET_BYTES = 20;

const DEFAULT_DIGITS = 6;
const DEFAULT_STEP_SECONDS = 30;

/** Encodes bytes as uppercase, unpadded base32 (the form authenticator apps expect). */
export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET.charAt((value >>> (bits - 5)) & 0x1f);
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET.charAt((value << (5 - bits)) & 0x1f);
  }

  return output;
}

/**
 * Decodes base32. Lowercase, spaces and `=` padding are tolerated because
 * users retype secrets from a screen; anything outside the alphabet is not.
 */
export function base32Decode(text: string): Buffer {
  const cleaned = text.replace(/[\s=]/g, '').toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);

    if (index === -1) throw new Error('invalid base32 input');

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/** Fresh 20-byte shared secret. Store it encrypted, never in plaintext. */
export function generateTotpSecret(): Buffer {
  return randomBytes(SECRET_BYTES);
}

/** One HOTP code: HMAC-SHA1, dynamic truncation, zero-padded to `digits`. */
export function hotp(secret: Buffer, counter: bigint, digits = DEFAULT_DIGITS): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);

  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = digest.readUInt8(digest.length - 1) & 0x0f;
  const truncated = digest.readUInt32BE(offset) & 0x7fff_ffff;

  return (truncated % 10 ** digits).toString().padStart(digits, '0');
}

export interface TotpOptions {
  readonly stepSeconds?: number;
  readonly digits?: number;
}

export interface VerifyTotpOptions extends TotpOptions {
  /** Number of steps accepted on either side of the current one. */
  readonly window?: number;
}

/** The code for the step that contains `timeMs`. */
export function totpAt(secret: Buffer, timeMs: number, options: TotpOptions = {}): string {
  const { stepSeconds = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS } = options;

  return hotp(secret, BigInt(Math.floor(timeMs / 1_000 / stepSeconds)), digits);
}

/**
 * Returns the time step that produced `code`, or null.
 *
 * The whole window is always checked and every comparison is constant-time, so
 * a near miss costs the same as a plain mismatch. Replay protection belongs to
 * the caller: stage 3.2b stores the last accepted step per user and refuses a
 * code whose step is not newer.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  nowMs: number,
  options: VerifyTotpOptions = {},
): number | null {
  const { window = 1, stepSeconds = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS } = options;

  // Anything but plain ASCII digits of the expected length cannot match, so it
  // is rejected before any HMAC work.
  if (typeof code !== 'string' || code.length !== digits || !/^[0-9]+$/.test(code)) {
    return null;
  }

  const codeBuffer = Buffer.from(code, 'ascii');
  const currentStep = Math.floor(nowMs / 1_000 / stepSeconds);
  let matchedStep: number | null = null;

  for (let delta = -window; delta <= window; delta += 1) {
    const step = currentStep + delta;

    if (step < 0) continue;

    const candidate = Buffer.from(hotp(secret, BigInt(step), digits), 'ascii');

    if (candidate.length === codeBuffer.length && timingSafeEqual(candidate, codeBuffer)) {
      matchedStep ??= step;
    }
  }

  return matchedStep;
}

export interface OtpauthUriInput {
  readonly issuer: string;
  /** Account label shown by the app (a username), never a raw phone number. */
  readonly label: string;
  readonly secretBase32: string;
}

/** Enrollment URI for authenticator apps. */
export function buildOtpauthUri({ issuer, label, secretBase32 }: OtpauthUriInput): string {
  // encodeURIComponent instead of URLSearchParams: apps expect %20, not '+'.
  const encode = (value: string): string => encodeURIComponent(value);
  const query = [
    `secret=${encode(secretBase32)}`,
    `issuer=${encode(issuer)}`,
    'algorithm=SHA1',
    'digits=6',
    'period=30',
  ].join('&');

  return `otpauth://totp/${encode(issuer)}:${encode(label)}?${query}`;
}
