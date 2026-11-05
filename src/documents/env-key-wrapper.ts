import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  decodeBase64Key,
  DOCUMENT_MASTER_KEY_BYTES,
  DOCUMENT_MASTER_KEY_DEFAULT_ID,
  type Env,
} from '../config/env';
import type { KeyWrapper, WrappedDataKey } from './key-wrapper';

/**
 * The local `KeyWrapper`: the master key comes from the environment and wraps
 * data keys with AES-256-GCM.
 *
 * One previous key may stay configured after a rotation. It is used for unwrap
 * only, so old documents keep decrypting while new ones are written under the
 * current key. Every failure - unknown label, wrong key, tampered blob - is
 * reported through the same error, and no error ever carries key material.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;
/** Layout of a wrapped key: `version | iv | tag | ciphertext`, so the size is fixed. */
const FORMAT_VERSION = 1;
const WRAPPED_BYTES = 1 + IV_BYTES + TAG_BYTES + DOCUMENT_MASTER_KEY_BYTES;

function unavailable(): Error {
  return new Error('document key unavailable');
}

/** Only the variable name is echoed: the value stays out of every message. */
function keyOf(value: string, name: string): Buffer {
  const key = decodeBase64Key(value, DOCUMENT_MASTER_KEY_BYTES);

  if (key === null) {
    throw new Error(
      `${name} must be base64 that decodes to exactly ${DOCUMENT_MASTER_KEY_BYTES} bytes`,
    );
  }

  return key;
}

/** The label is authenticated, so a blob relabelled to another version fails. */
function aadFor(keyId: string): Buffer {
  return Buffer.from(`kfa:document-dek:${keyId}`, 'utf8');
}

export interface EnvKeyWrapperOptions {
  /** Base64 of exactly 32 bytes. */
  readonly masterKey: string;
  readonly masterKeyId?: string;
  /** Base64 of exactly 32 bytes; unwrap only. */
  readonly previousMasterKey?: string;
  readonly previousMasterKeyId?: string;
}

export class EnvKeyWrapper implements KeyWrapper {
  private readonly currentKeyId: string;
  /** Every usable label, current first. */
  private readonly keys = new Map<string, Buffer>();

  constructor(options: EnvKeyWrapperOptions) {
    this.currentKeyId = options.masterKeyId ?? DOCUMENT_MASTER_KEY_DEFAULT_ID;
    this.keys.set(this.currentKeyId, keyOf(options.masterKey, 'DOCUMENT_MASTER_KEY'));

    if (options.previousMasterKey !== undefined) {
      if (options.previousMasterKeyId === undefined) {
        throw new Error(
          'DOCUMENT_MASTER_KEY_PREVIOUS_ID is required next to DOCUMENT_MASTER_KEY_PREVIOUS',
        );
      }

      if (options.previousMasterKeyId === this.currentKeyId) {
        throw new Error('DOCUMENT_MASTER_KEY_ID and DOCUMENT_MASTER_KEY_PREVIOUS_ID must differ');
      }

      this.keys.set(
        options.previousMasterKeyId,
        keyOf(options.previousMasterKey, 'DOCUMENT_MASTER_KEY_PREVIOUS'),
      );
    }
  }

  /**
   * Builds the wrapper from the validated environment, or refuses to start.
   * The environment validator already rejects a malformed key; repeating the
   * check here keeps any wiring that skips `loadEnv` from running unencrypted.
   */
  static fromEnv(
    env: Pick<
      Env,
      | 'DOCUMENT_MASTER_KEY'
      | 'DOCUMENT_MASTER_KEY_ID'
      | 'DOCUMENT_MASTER_KEY_PREVIOUS'
      | 'DOCUMENT_MASTER_KEY_PREVIOUS_ID'
    >,
  ): EnvKeyWrapper {
    if (env.DOCUMENT_MASTER_KEY === undefined) {
      throw new Error('DOCUMENT_MASTER_KEY is required to store documents');
    }

    return new EnvKeyWrapper({
      masterKey: env.DOCUMENT_MASTER_KEY,
      masterKeyId: env.DOCUMENT_MASTER_KEY_ID,
      previousMasterKey: env.DOCUMENT_MASTER_KEY_PREVIOUS,
      previousMasterKeyId: env.DOCUMENT_MASTER_KEY_PREVIOUS_ID,
    });
  }

  async wrap(dek: Buffer): Promise<WrappedDataKey> {
    const key = this.keys.get(this.currentKeyId);

    if (key === undefined || dek.length !== DOCUMENT_MASTER_KEY_BYTES) throw unavailable();

    // A fresh IV per call: reusing one under the same key would break GCM.
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aadFor(this.currentKeyId));

    const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);

    return {
      keyId: this.currentKeyId,
      wrapped: Buffer.concat([Buffer.from([FORMAT_VERSION]), iv, cipher.getAuthTag(), ciphertext]),
    };
  }

  async unwrap(keyId: string, wrapped: Buffer): Promise<Buffer> {
    try {
      const key = this.keys.get(keyId);

      if (key === undefined) throw unavailable();
      if (wrapped.length !== WRAPPED_BYTES || wrapped[0] !== FORMAT_VERSION) throw unavailable();

      const iv = wrapped.subarray(1, 1 + IV_BYTES);
      const tag = wrapped.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
      const ciphertext = wrapped.subarray(1 + IV_BYTES + TAG_BYTES);

      const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
      decipher.setAAD(aadFor(keyId));
      decipher.setAuthTag(tag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      // Wrong label, wrong key, wrong format and a tampered blob all land here.
      throw unavailable();
    }
  }
}
