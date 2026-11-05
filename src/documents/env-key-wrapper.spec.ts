import { EnvKeyWrapper } from './env-key-wrapper';

/**
 * Fixed, fake master keys: base64 of exactly 32 bytes. Tests must never depend
 * on a real key, and a key never leaves this file.
 */
const MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=';
const OTHER_MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXItazI=';
const DEK = Buffer.alloc(32, 0x33);

function messageOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    return (error as Error).message;
  }

  throw new Error('expected the call to fail');
}

/** Replaces one byte of the wrapped blob, so the ciphertext really changes. */
function tamper(wrapped: Buffer, index: number): Buffer {
  const copy = Buffer.from(wrapped);
  const current = copy[index] as number;

  copy[index] = current === 0xff ? 0x00 : current + 1;

  return copy;
}

describe('EnvKeyWrapper', () => {
  const wrapper = new EnvKeyWrapper({ masterKey: MASTER_KEY });

  it('wraps and unwraps a data key', async () => {
    const { keyId, wrapped } = await wrapper.wrap(DEK);

    expect(keyId).toBe('v1');
    expect(wrapped).toHaveLength(1 + 12 + 16 + 32);
    expect(await wrapper.unwrap(keyId, wrapped)).toEqual(DEK);
  });

  it('uses a fresh iv per call', async () => {
    const first = await wrapper.wrap(DEK);
    const second = await wrapper.wrap(DEK);

    expect(first.wrapped.equals(second.wrapped)).toBe(false);
    expect(await wrapper.unwrap(second.keyId, second.wrapped)).toEqual(DEK);
  });

  it('keeps the data key out of the wrapped blob', async () => {
    const { wrapped } = await wrapper.wrap(DEK);

    expect(wrapped.includes(DEK)).toBe(false);
  });

  it('accepts a key id override', async () => {
    const labelled = new EnvKeyWrapper({ masterKey: MASTER_KEY, masterKeyId: 'v7' });
    const { keyId, wrapped } = await labelled.wrap(DEK);

    expect(keyId).toBe('v7');
    expect(await labelled.unwrap('v7', wrapped)).toEqual(DEK);
  });

  it('refuses an unknown key id', async () => {
    const { wrapped } = await wrapper.wrap(DEK);

    await expect(wrapper.unwrap('v2', wrapped)).rejects.toThrow('document key unavailable');
  });

  it.each([
    ['header', 0],
    ['iv', 2],
    ['tag', 20],
    ['ciphertext', 40],
  ])('refuses a tampered %s', async (_label, index) => {
    const { keyId, wrapped } = await wrapper.wrap(DEK);

    await expect(wrapper.unwrap(keyId, tamper(wrapped, index))).rejects.toThrow(
      'document key unavailable',
    );
  });

  it('refuses a truncated or oversized blob', async () => {
    const { keyId, wrapped } = await wrapper.wrap(DEK);

    await expect(wrapper.unwrap(keyId, wrapped.subarray(0, wrapped.length - 1))).rejects.toThrow(
      'document key unavailable',
    );
    await expect(wrapper.unwrap(keyId, Buffer.concat([wrapped, Buffer.from([0])]))).rejects.toThrow(
      'document key unavailable',
    );
  });

  it('refuses the wrong master key', async () => {
    const other = new EnvKeyWrapper({ masterKey: OTHER_MASTER_KEY });
    const { keyId, wrapped } = await wrapper.wrap(DEK);

    await expect(other.unwrap(keyId, wrapped)).rejects.toThrow('document key unavailable');
  });

  it('binds a wrapped key to its label', async () => {
    // Same key material, only the label it is looked up under differs: this shows
    // the label is authenticated, not merely used as a map key.
    const relabelled = new EnvKeyWrapper({
      masterKey: MASTER_KEY,
      masterKeyId: 'v2',
      previousMasterKey: MASTER_KEY,
      previousMasterKeyId: 'v9',
    });
    const { wrapped } = await wrapper.wrap(DEK);

    await expect(relabelled.unwrap('v9', wrapped)).rejects.toThrow('document key unavailable');
  });

  it('still unwraps with the previous key after a rotation', async () => {
    const rotation = new EnvKeyWrapper({
      masterKey: OTHER_MASTER_KEY,
      masterKeyId: 'v2',
      previousMasterKey: MASTER_KEY,
      previousMasterKeyId: 'v1',
    });

    const before = await wrapper.wrap(DEK);
    const after = await rotation.wrap(DEK);

    expect(after.keyId).toBe('v2');
    expect(await rotation.unwrap(before.keyId, before.wrapped)).toEqual(DEK);
    expect(await rotation.unwrap(after.keyId, after.wrapped)).toEqual(DEK);
  });

  it.each([
    ['a master key of 31 bytes', { masterKey: Buffer.alloc(31, 1).toString('base64') }],
    ['a master key of 33 bytes', { masterKey: Buffer.alloc(33, 1).toString('base64') }],
    ['a master key that is not base64', { masterKey: 'not+a+key' }],
  ])('rejects %s', (_label, options) => {
    expect(() => new EnvKeyWrapper(options)).toThrow(/DOCUMENT_MASTER_KEY/);
  });

  it('rejects an unusable previous key', () => {
    expect(
      () => new EnvKeyWrapper({ masterKey: MASTER_KEY, previousMasterKey: MASTER_KEY }),
    ).toThrow(/DOCUMENT_MASTER_KEY_PREVIOUS_ID/);
    expect(
      () =>
        new EnvKeyWrapper({
          masterKey: MASTER_KEY,
          masterKeyId: 'v1',
          previousMasterKey: OTHER_MASTER_KEY,
          previousMasterKeyId: 'v1',
        }),
    ).toThrow(/must differ/);
    expect(
      () =>
        new EnvKeyWrapper({
          masterKey: MASTER_KEY,
          previousMasterKey: Buffer.alloc(16, 1).toString('base64'),
          previousMasterKeyId: 'v0',
        }),
    ).toThrow(/DOCUMENT_MASTER_KEY_PREVIOUS/);
  });

  it('never echoes key material in a failure', async () => {
    const rawKey = Buffer.from(MASTER_KEY, 'base64');
    const other = new EnvKeyWrapper({ masterKey: OTHER_MASTER_KEY });
    const { keyId, wrapped } = await wrapper.wrap(DEK);
    const messages = [
      messageOf(() => new EnvKeyWrapper({ masterKey: 'too-short' })),
      messageOf(() => new EnvKeyWrapper({ masterKey: MASTER_KEY, previousMasterKey: MASTER_KEY })),
      await wrapper.unwrap('unknown', wrapped).catch((error: Error) => error.message),
      await other.unwrap(keyId, wrapped).catch((error: Error) => error.message),
      await other.unwrap(keyId, tamper(wrapped, 30)).catch((error: Error) => error.message),
    ];

    for (const message of messages) {
      expect(message).not.toContain(MASTER_KEY);
      expect(message).not.toContain(OTHER_MASTER_KEY);
      expect(message).not.toContain(rawKey.toString('latin1'));
    }
  });

  it('builds from the environment and refuses a missing key', () => {
    const fromEnv = EnvKeyWrapper.fromEnv({ DOCUMENT_MASTER_KEY: MASTER_KEY });

    expect(fromEnv).toBeInstanceOf(EnvKeyWrapper);
    expect(() => EnvKeyWrapper.fromEnv({ DOCUMENT_MASTER_KEY: undefined })).toThrow(
      /DOCUMENT_MASTER_KEY is required/,
    );
  });
});
