import type { DocumentStorage } from './document-storage';

/**
 * Test-only storage: a map, no disk, no network, no bucket.
 *
 * It copies every buffer in and out, so a caller cannot rewrite a stored blob by
 * keeping the array it wrote (or read) around - the same isolation a real object
 * store gives for free.
 */
export class InMemoryDocumentStorage implements DocumentStorage {
  private readonly objects = new Map<string, Buffer>();

  async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.objects.set(objectKey, Buffer.from(bytes));
  }

  async get(objectKey: string): Promise<Buffer> {
    const stored = this.objects.get(objectKey);

    // The key itself is never echoed: a caller learns "missing", nothing more.
    if (stored === undefined) throw new Error('document not found');

    return Buffer.from(stored);
  }

  async delete(objectKey: string): Promise<void> {
    this.objects.delete(objectKey);
  }

  async exists(objectKey: string): Promise<boolean> {
    return this.objects.has(objectKey);
  }
}
