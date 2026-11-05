import { DocumentCryptoService, type EncryptedDocument } from './document-crypto.service';
import { EnvKeyWrapper, type EnvKeyWrapperOptions } from './env-key-wrapper';

/** Fixed, fake master keys: base64 of exactly 32 bytes. */
const MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=';
const OTHER_MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXItazI=';
const OBJECT_KEY = '9b2f5c18-2e04-4a7b-9f2e-0b7d1c3a5e60';
const OTHER_OBJECT_KEY = '1c0d8a54-6b31-4f2e-8a5f-2d9e0c4b7f31';
/** Stands in for a scanned document: fake bytes, nothing personal in them. */
const DOCUMENT_BYTES = Buffer.from('fake-identity-document-scan', 'utf8');

function serviceWith(options: EnvKeyWrapperOptions): DocumentCryptoService {
  return new DocumentCryptoService(new EnvKeyWrapper(options));
}

const service = serviceWith({ masterKey: MASTER_KEY });

/** Flips the first byte, so the field a test corrupts really changes. */
function tamper(bytes: Buffer): Buffer {
  const copy = Buffer.from(bytes);

  copy[0] = (copy[0] as number) ^ 0xff;

  return copy;
}

describe('DocumentCryptoService', () => {
  it('round-trips a document', async () => {
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    expect(encrypted.keyId).toBe('v1');
    expect(encrypted.iv).toHaveLength(12);
    expect(encrypted.authTag).toHaveLength(16);
    expect(await service.decrypt(encrypted, OBJECT_KEY)).toEqual(DOCUMENT_BYTES);
  });

  it('never stores the plaintext', async () => {
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    expect(encrypted.ciphertext.includes(DOCUMENT_BYTES)).toBe(false);
    expect(encrypted.wrappedDek.includes(DOCUMENT_BYTES)).toBe(false);
  });

  it('encrypts the same plaintext differently every time', async () => {
    const first = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);
    const second = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    // A fresh data key and a fresh IV per call, so nothing repeats.
    expect(first.ciphertext.equals(second.ciphertext)).toBe(false);
    expect(first.iv.equals(second.iv)).toBe(false);
    expect(first.wrappedDek.equals(second.wrappedDek)).toBe(false);
    expect(await service.decrypt(second, OBJECT_KEY)).toEqual(DOCUMENT_BYTES);
  });

  it('refuses a document read under another object key', async () => {
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    await expect(service.decrypt(encrypted, OTHER_OBJECT_KEY)).rejects.toThrow(
      'document unreadable',
    );
  });

  it.each([
    [
      'ciphertext',
      (document: EncryptedDocument): EncryptedDocument => ({
        ...document,
        ciphertext: tamper(document.ciphertext),
      }),
    ],
    [
      'auth tag',
      (document: EncryptedDocument): EncryptedDocument => ({
        ...document,
        authTag: tamper(document.authTag),
      }),
    ],
    [
      'iv',
      (document: EncryptedDocument): EncryptedDocument => ({
        ...document,
        iv: tamper(document.iv),
      }),
    ],
    [
      'wrapped data key',
      (document: EncryptedDocument): EncryptedDocument => ({
        ...document,
        wrappedDek: tamper(document.wrappedDek),
      }),
    ],
    [
      'key id',
      (document: EncryptedDocument): EncryptedDocument => ({
        ...document,
        keyId: 'v9',
      }),
    ],
  ])('refuses a tampered %s', async (_label, corrupt) => {
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    await expect(service.decrypt(corrupt(encrypted), OBJECT_KEY)).rejects.toThrow(
      'document unreadable',
    );
  });

  it('refuses a document wrapped under a different master key', async () => {
    const other = serviceWith({ masterKey: OTHER_MASTER_KEY });
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    await expect(other.decrypt(encrypted, OBJECT_KEY)).rejects.toThrow('document unreadable');
  });

  it('decrypts a document wrapped before a master-key rotation', async () => {
    const rotation = serviceWith({
      masterKey: OTHER_MASTER_KEY,
      masterKeyId: 'v2',
      previousMasterKey: MASTER_KEY,
      previousMasterKeyId: 'v1',
    });

    const before = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);
    const after = await rotation.encrypt(DOCUMENT_BYTES, OBJECT_KEY);

    expect(after.keyId).toBe('v2');
    expect(await rotation.decrypt(before, OBJECT_KEY)).toEqual(DOCUMENT_BYTES);
  });

  it('reports every failure the same way, without leaking material', async () => {
    const other = serviceWith({ masterKey: OTHER_MASTER_KEY });
    const encrypted = await service.encrypt(DOCUMENT_BYTES, OBJECT_KEY);
    const messages = [
      await service.decrypt(encrypted, OTHER_OBJECT_KEY).catch((error: Error) => error.message),
      await other.decrypt(encrypted, OBJECT_KEY).catch((error: Error) => error.message),
      await service
        .decrypt({ ...encrypted, authTag: tamper(encrypted.authTag) }, OBJECT_KEY)
        .catch((error: Error) => error.message),
      await service
        .decrypt({ ...encrypted, iv: Buffer.alloc(4) }, OBJECT_KEY)
        .catch((error: Error) => error.message),
    ];

    expect(new Set(messages)).toEqual(new Set(['document unreadable']));

    for (const message of messages) {
      expect(message).not.toContain(MASTER_KEY);
      expect(message).not.toContain(OTHER_MASTER_KEY);
      expect(message).not.toContain(DOCUMENT_BYTES.toString('utf8'));
    }
  });
});
