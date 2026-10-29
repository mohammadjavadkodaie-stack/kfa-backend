import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Encrypts the TOTP shared secret at rest (AES-256-GCM).
 *
 * The user id is used as AAD, so a ciphertext copied onto another account no
 * longer decrypts. Every failure is reported through one generic error: the
 * caller learns "unusable", never why.
 */

/** Key rotation will add a `v2` format; the version prefix is where it plugs in. */
const VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const PART_COUNT = 4;

function unreadable(): Error {
  return new Error('totp secret unreadable');
}

function assertKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) throw unreadable();
}

/** Returns `v1.<iv>.<ciphertext>.<tag>`, all base64url. */
export function encryptTotpSecret(secret: Buffer, key: Buffer, userId: string): string {
  assertKey(key);

  // A fresh IV per call: reusing one under the same key would break GCM.
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(userId, 'utf8'));

  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);

  return [
    VERSION,
    iv.toString('base64url'),
    ciphertext.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
  ].join('.');
}

/** Inverse of `encryptTotpSecret`; throws the generic error on any mismatch. */
export function decryptTotpSecret(stored: string, key: Buffer, userId: string): Buffer {
  try {
    assertKey(key);

    const parts = stored.split('.');

    if (parts.length !== PART_COUNT || parts[0] !== VERSION) throw unreadable();

    const iv = Buffer.from(parts[1] as string, 'base64url');
    const ciphertext = Buffer.from(parts[2] as string, 'base64url');
    const tag = Buffer.from(parts[3] as string, 'base64url');

    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw unreadable();

    const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(userId, 'utf8'));
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // Tag mismatch, wrong key and wrong user id all land here, indistinguishably.
    throw unreadable();
  }
}
