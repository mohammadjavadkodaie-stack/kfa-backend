import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { KeyWrapper } from './key-wrapper';

/**
 * Envelope encryption for identity documents.
 *
 * Every document is encrypted under its own random data key, and only that data
 * key is wrapped by the `KeyWrapper`. A future KMS therefore never has to touch
 * the document bytes, and rotating the master key only re-wraps small keys.
 *
 * The object key is passed as AAD: it is authenticated but not stored, so a blob
 * copied under another object key no longer decrypts.
 */

const ALGORITHM = 'aes-256-gcm';
const DEK_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

function unreadable(): Error {
  return new Error('document unreadable');
}

/** Everything needed to read a document back; none of it is secret on its own. */
export interface EncryptedDocument {
  readonly ciphertext: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;
  readonly wrappedDek: Buffer;
  readonly keyId: string;
}

export class DocumentCryptoService {
  constructor(private readonly keyWrapper: KeyWrapper) {}

  /** Encrypts `plaintext`; `aad` is the object key the blob will be stored under. */
  async encrypt(plaintext: Buffer, aad: string): Promise<EncryptedDocument> {
    // A fresh data key and a fresh IV per call: reusing either under one key
    // would break GCM.
    const dek = randomBytes(DEK_BYTES);

    try {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv(ALGORITHM, dek, iv, { authTagLength: TAG_BYTES });
      cipher.setAAD(Buffer.from(aad, 'utf8'));

      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const { keyId, wrapped } = await this.keyWrapper.wrap(dek);

      return { ciphertext, iv, authTag: cipher.getAuthTag(), wrappedDek: wrapped, keyId };
    } finally {
      // Best effort: the data key must not linger in this buffer.
      dek.fill(0);
    }
  }

  /** Inverse of `encrypt`; every failure is reported as the same generic error. */
  async decrypt(document: EncryptedDocument, aad: string): Promise<Buffer> {
    let dek: Buffer | null = null;

    try {
      if (document.iv.length !== IV_BYTES || document.authTag.length !== TAG_BYTES) {
        throw unreadable();
      }

      dek = await this.keyWrapper.unwrap(document.keyId, document.wrappedDek);

      if (dek.length !== DEK_BYTES) throw unreadable();

      const decipher = createDecipheriv(ALGORITHM, dek, document.iv, {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(Buffer.from(aad, 'utf8'));
      decipher.setAuthTag(document.authTag);

      return Buffer.concat([decipher.update(document.ciphertext), decipher.final()]);
    } catch {
      // Wrong AAD, wrong key, tampered blob and a broken wrapper call all land here.
      throw unreadable();
    } finally {
      dek?.fill(0);
    }
  }
}
