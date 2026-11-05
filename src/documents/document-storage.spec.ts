import { createObjectKey, type DocumentStorage } from './document-storage';
import { InMemoryDocumentStorage } from './in-memory-document-storage';

const BYTES = Buffer.from('ciphertext-for-one-document', 'utf8');

describe('createObjectKey', () => {
  it('returns a random uuid', () => {
    expect(createObjectKey()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('never repeats a key', () => {
    const keys = new Set(Array.from({ length: 200 }, () => createObjectKey()));

    expect(keys.size).toBe(200);
  });

  it('carries no owner, name or extension', () => {
    for (const key of Array.from({ length: 20 }, () => createObjectKey())) {
      expect(key).not.toContain('/');
      expect(key).not.toContain('\\');
      expect(key).not.toContain('..');
      expect(key).not.toContain('.pdf');
      expect(key).not.toContain('.jpg');
    }
  });
});

describe('InMemoryDocumentStorage', () => {
  const storage: DocumentStorage = new InMemoryDocumentStorage();

  it('puts, reads and deletes an object', async () => {
    const objectKey = createObjectKey();

    expect(await storage.exists(objectKey)).toBe(false);

    await storage.put(objectKey, BYTES);

    expect(await storage.exists(objectKey)).toBe(true);
    expect(await storage.get(objectKey)).toEqual(BYTES);

    await storage.delete(objectKey);

    expect(await storage.exists(objectKey)).toBe(false);
  });

  it('keeps objects apart', async () => {
    const first = createObjectKey();
    const second = createObjectKey();

    await storage.put(first, BYTES);
    await storage.put(second, Buffer.from('another', 'utf8'));

    expect(await storage.get(first)).toEqual(BYTES);
    expect(await storage.get(second)).toEqual(Buffer.from('another', 'utf8'));
  });

  it('copies bytes in and out', async () => {
    const objectKey = createObjectKey();
    const written = Buffer.from(BYTES);

    await storage.put(objectKey, written);
    written[0] = 0x00;

    expect(await storage.get(objectKey)).toEqual(BYTES);

    const read = await storage.get(objectKey);
    read[0] = 0x00;

    expect(await storage.get(objectKey)).toEqual(BYTES);
  });

  it('reports a missing object with a generic error', async () => {
    const objectKey = createObjectKey();
    const message = await storage.get(objectKey).catch((error: Error) => error.message);

    // The caller learns "missing" and nothing about the key it asked for.
    expect(message).toBe('document not found');
    expect(message).not.toContain(objectKey);
  });

  it('treats deleting a missing object as done', async () => {
    await expect(storage.delete(createObjectKey())).resolves.toBeUndefined();
  });
});
