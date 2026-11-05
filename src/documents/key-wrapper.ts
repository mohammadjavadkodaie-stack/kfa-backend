/**
 * The seam between envelope encryption and a key management service.
 *
 * A data key never leaves this process in the clear: `wrap` hands it to the
 * wrapper, which returns the ciphertext plus the label of the key version that
 * produced it, and `unwrap` turns that pair back into the data key. A future KMS
 * adapter implements the same interface, so `DocumentCryptoService` is written
 * once and never learns where the master key lives.
 */

/** One wrapped data key: what a row has to keep to read the blob back. */
export interface WrappedDataKey {
  readonly keyId: string;
  readonly wrapped: Buffer;
}

export interface KeyWrapper {
  /** Encrypts a freshly generated data key. */
  wrap(dek: Buffer): Promise<WrappedDataKey>;
  /** Reverses `wrap`; the returned buffer belongs to the caller and should be zeroed. */
  unwrap(keyId: string, wrapped: Buffer): Promise<Buffer>;
}

/** DI token for a `KeyWrapper` implementation. */
export const KEY_WRAPPER = Symbol('KEY_WRAPPER');
