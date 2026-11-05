import type { Readable } from 'node:stream';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import type { DocumentStorage } from './document-storage';

/**
 * S3-compatible object store for encrypted documents (MinIO in dev/test, any
 * S3-compatible service elsewhere).
 *
 * Everything this adapter sees is already ciphertext: `DocumentCryptoService`
 * encrypts before `put` and decrypts after `get`, so no plaintext ever reaches
 * a bucket. Two deliberate omissions follow from that:
 *
 * - no ACL is ever set, so an object is exactly as private as the bucket policy;
 * - no URL is ever produced, so there is nothing to leak: callers pass an object
 *   key in and get bytes back, never a link that could be shared or cached.
 */

/** Largest object this adapter will read back in one piece (20 MiB). */
export const MAX_DOCUMENT_BYTES = 20 * 1024 * 1024;

/**
 * Region handed to SigV4 when S3_REGION is unset. MinIO and most compatible
 * stores ignore it, but a signature cannot be computed without one.
 */
const DEFAULT_REGION = 'us-east-1';

const NOT_FOUND = 'document not found';
const UNAVAILABLE = 'document storage unavailable';

/** Everything the adapter needs; a subset of `Env`, so tests can pass fixtures. */
export interface S3DocumentStorageConfig {
  readonly S3_ENDPOINT: string;
  readonly S3_REGION?: string;
  readonly S3_BUCKET: string;
  readonly S3_ACCESS_KEY_ID: string;
  readonly S3_SECRET_ACCESS_KEY: string;
  readonly S3_FORCE_PATH_STYLE?: boolean;
}

/**
 * One generic failure for every S3 problem. The original error is dropped on
 * purpose: its message and metadata name the bucket, the key and the endpoint.
 */
function unavailable(): Error {
  return new Error(UNAVAILABLE);
}

/** Missing object: the same wording the in-memory adapter uses. */
function notFound(): Error {
  return new Error(NOT_FOUND);
}

/**
 * True for the two "there is nothing there" responses: GetObject reports
 * NoSuchKey, HeadObject reports a bare 404 that the SDK names NotFound.
 */
function isMissing(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;

  const { name, $metadata } = error as {
    name?: unknown;
    $metadata?: { httpStatusCode?: unknown };
  };

  return name === 'NotFound' || name === 'NoSuchKey' || $metadata?.httpStatusCode === 404;
}

/**
 * Builds the client from the environment: path-style addressing and credentials
 * are explicit so the adapter never falls back to an instance role or to the
 * credentials of whatever host it happens to run on.
 */
export function createS3Client(config: S3DocumentStorageConfig): S3Client {
  return new S3Client({
    endpoint: config.S3_ENDPOINT,
    region: config.S3_REGION ?? DEFAULT_REGION,
    forcePathStyle: config.S3_FORCE_PATH_STYLE ?? false,
    credentials: {
      accessKeyId: config.S3_ACCESS_KEY_ID,
      secretAccessKey: config.S3_SECRET_ACCESS_KEY,
    },
  });
}

/**
 * Collects a response body, counting as it goes: an object that grows past the
 * cap is destroyed instead of being buffered, so a wrong Content-Length cannot
 * turn into an unbounded allocation.
 */
async function readCapped(body: unknown, maxBytes: number): Promise<Buffer> {
  const stream = body as Readable;
  const chunks: Buffer[] = [];
  let total = 0;

  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);

    total += bytes.byteLength;

    if (total > maxBytes) {
      stream.destroy();
      throw unavailable();
    }

    chunks.push(bytes);
  }

  return Buffer.concat(chunks, total);
}

export class S3DocumentStorage implements DocumentStorage {
  private readonly client: S3Client;
  private readonly bucket: string;

  /**
   * The client is injectable so unit tests can record commands without a
   * network round trip; every real call site builds it from the environment.
   */
  constructor(config: S3DocumentStorageConfig, client: S3Client = createS3Client(config)) {
    this.bucket = config.S3_BUCKET;
    this.client = client;
  }

  async put(objectKey: string, bytes: Buffer): Promise<void> {
    try {
      // No ACL: the bucket policy decides who may read, and nothing here may
      // make an object more public than the bucket already is.
      await this.client.send(
        new PutObjectCommand({ Bucket: this.bucket, Key: objectKey, Body: bytes }),
      );
    } catch {
      throw unavailable();
    }
  }

  async get(objectKey: string): Promise<Buffer> {
    const response = await this.client
      .send(new GetObjectCommand({ Bucket: this.bucket, Key: objectKey }))
      .catch((error: unknown) => {
        throw isMissing(error) ? notFound() : unavailable();
      });

    if (response.Body === undefined) throw unavailable();

    // A declared size above the cap is refused before a single byte is read.
    if (typeof response.ContentLength === 'number' && response.ContentLength > MAX_DOCUMENT_BYTES) {
      throw unavailable();
    }

    try {
      return await readCapped(response.Body, MAX_DOCUMENT_BYTES);
    } catch {
      throw unavailable();
    }
  }

  /**
   * S3 answers 204 even when the key was not there, so a delete needs no special
   * case: the intent ("this object is gone") is satisfied either way.
   */
  async delete(objectKey: string): Promise<void> {
    try {
      await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: objectKey }));
    } catch {
      throw unavailable();
    }
  }

  async exists(objectKey: string): Promise<boolean> {
    try {
      // HeadObject moves no body: the answer is the status code alone.
      await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: objectKey }));
      return true;
    } catch (error) {
      // Only "not there" is an answer; any other failure is a real outage.
      if (isMissing(error)) return false;

      throw unavailable();
    }
  }
}
