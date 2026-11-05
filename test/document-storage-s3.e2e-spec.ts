import { randomUUID } from 'node:crypto';
import type { S3Client } from '@aws-sdk/client-s3';
import {
  createS3Client,
  S3DocumentStorage,
  type S3DocumentStorageConfig,
} from '../src/documents/s3-document-storage';

/**
 * Real-MinIO suite for the S3 adapter. Skipped unless every `*_TEST` setting is
 * present, so the default `pnpm test:e2e` run (and CI) never reaches a bucket:
 *
 *   S3_ENDPOINT_TEST=http://127.0.0.1:9000 \
 *   S3_BUCKET_TEST=kfa-documents \
 *   S3_ACCESS_KEY_ID_TEST=test-only-minio-access-key \
 *   S3_SECRET_ACCESS_KEY_TEST=test-only-minio-secret-key \
 *   pnpm test:e2e test/document-storage-s3
 *
 * Point it at a THROWAWAY MinIO only (the `minio` service in
 * docker-compose.dev.yml); the suite writes and deletes its own object keys.
 * The bucket has to exist already (the `minio-init` service creates it) and has
 * to stay private: the last test asserts that, so a public bucket fails here.
 */
interface S3TestSettings {
  readonly endpoint: string;
  readonly bucket: string;
  readonly config: S3DocumentStorageConfig;
}

function isSet(value: string | undefined): value is string {
  return value !== undefined && value.trim() !== '';
}

function readSettings(): S3TestSettings | undefined {
  const endpoint = process.env.S3_ENDPOINT_TEST;
  const bucket = process.env.S3_BUCKET_TEST;
  const accessKeyId = process.env.S3_ACCESS_KEY_ID_TEST;
  const secretAccessKey = process.env.S3_SECRET_ACCESS_KEY_TEST;

  if (!isSet(endpoint) || !isSet(bucket) || !isSet(accessKeyId) || !isSet(secretAccessKey)) {
    return undefined;
  }

  return {
    endpoint,
    bucket,
    config: {
      S3_ENDPOINT: endpoint,
      S3_BUCKET: bucket,
      S3_ACCESS_KEY_ID: accessKeyId,
      S3_SECRET_ACCESS_KEY: secretAccessKey,
      // MinIO only answers path-style requests, and the object URL below has to
      // address the store the same way the client does.
      S3_FORCE_PATH_STYLE: true,
    },
  };
}

const SETTINGS = readSettings();

const describeWithS3 = SETTINGS === undefined ? describe.skip : describe;

describeWithS3('S3 document storage against MinIO (e2e)', () => {
  let client: S3Client;
  let storage: S3DocumentStorage;
  let objectUrl: (objectKey: string) => string;

  /** Unique per run, so a leftover key from an aborted run cannot be observed. */
  const prefix = `e2e-${randomUUID()}`;
  const objectKey = `${prefix}/document.bin`;
  const payload = Buffer.from('test-only document ciphertext', 'utf8');

  beforeAll(() => {
    if (SETTINGS === undefined) {
      return;
    }

    const settings = SETTINGS;

    client = createS3Client(settings.config);
    storage = new S3DocumentStorage(settings.config, client);
    objectUrl = (key: string): string =>
      `${settings.endpoint.replace(/\/+$/, '')}/${settings.bucket}/${key}`;
  });

  afterAll(async () => {
    if (SETTINGS === undefined) {
      return;
    }

    // The round trip deletes its own key; this only covers a failed assertion.
    await storage.delete(objectKey).catch(() => undefined);
    client.destroy();
  });

  it('round-trips an object through put, get, exists and delete', async () => {
    await storage.put(objectKey, payload);
    await expect(storage.exists(objectKey)).resolves.toBe(true);

    // get returns exactly the bytes that were written: no re-encoding, no
    // truncation at the 20 MiB cap.
    await expect(storage.get(objectKey)).resolves.toEqual(payload);

    await storage.delete(objectKey);
    await expect(storage.exists(objectKey)).resolves.toBe(false);
  });

  it('reports a missing object instead of inventing one', async () => {
    const missing = `${prefix}/missing.bin`;

    // GetObject and HeadObject name the same condition differently; the adapter
    // folds both into one error, and a delete of an absent key stays a no-op.
    await expect(storage.get(missing)).rejects.toThrow('document not found');
    await expect(storage.exists(missing)).resolves.toBe(false);
    await expect(storage.delete(missing)).resolves.toBeUndefined();
  });

  it('refuses an unauthenticated GET of the object URL', async () => {
    await storage.put(objectKey, payload);

    // No signature, no credentials and no query string: exactly what a leaked
    // object URL would be worth against a private bucket.
    const response = await fetch(objectUrl(objectKey));
    const body = await response.text();

    // Reported so a real run states the observed status rather than only
    // "expected 403": MinIO answers 403 AccessDenied for an anonymous read.
    process.stdout.write(`[s3-e2e] unauthenticated GET status: ${response.status}\n`);

    expect(response.status).toBe(403);
    // A denial must not leak the object either.
    expect(body).not.toContain('test-only document ciphertext');

    await storage.delete(objectKey);
  });
});
