import { randomUUID } from 'node:crypto';

/**
 * Where encrypted document bytes live.
 *
 * Deliberately abstract: the crypto layer only ever hands over an opaque object
 * key and ciphertext, so a local disk, MinIO or S3 adapter can be added later
 * without touching encryption.
 */
export interface DocumentStorage {
  put(objectKey: string, bytes: Buffer): Promise<void>;
  get(objectKey: string): Promise<Buffer>;
  /** Deleting a missing object is not an error: the intent is already satisfied. */
  delete(objectKey: string): Promise<void>;
  exists(objectKey: string): Promise<boolean>;
}

/** DI token for a `DocumentStorage` implementation. */
export const DOCUMENT_STORAGE = Symbol('DOCUMENT_STORAGE');

/**
 * A random object key.
 *
 * It carries no user id, file name or extension on purpose: given a stored blob,
 * the storage layer must not be able to say whose document it is or what it was
 * called.
 */
export function createObjectKey(): string {
  return randomUUID();
}
