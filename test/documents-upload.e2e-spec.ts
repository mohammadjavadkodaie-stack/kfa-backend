import { createHash } from 'node:crypto';
import { DocumentKind } from '@prisma/client';
import { Role } from '../src/auth/roles';
import type { DocumentStorage } from '../src/documents/document-storage';
import { InMemoryDocumentStorage } from '../src/documents/in-memory-document-storage';
import { MAX_UPLOAD_BYTES, MIN_UPLOAD_BYTES } from '../src/documents/ingest/ingest.constants';
import { FakeVirusScanner } from '../src/documents/ingest/testing/fake-virus-scanner';
import {
  buildJpeg,
  buildPng,
  COMMENT_SEGMENT,
  pngChunks,
  TEXT_CHUNK,
  truncatedTo,
  withTrailingBytes,
} from '../src/documents/ingest/testing/image-fixtures';
import {
  DOCUMENT_AUDIT_ACTIONS,
  MAX_ACTIVE_DOCUMENTS,
} from '../src/documents/records/document-upload.service';
import { InMemoryIdentityDocuments } from '../src/documents/records/testing/in-memory-identity-documents';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../src/rate-limit/rate-limit.service';
import type { AdminAccount } from './helpers/admin-harness';
import { createAdminHarness } from './helpers/admin-harness';
import { createDocumentHarness, uploadTo, type DocumentHarness } from './helpers/document-harness';
import { TEST_ENV } from './helpers/test-env';

/**
 * Stage 4.3c: the document upload route over the real application.
 *
 * The raw parser, the guards, the pipe, the pipeline, the audit trail and the
 * limits are the real ones; only the table, the bucket and the daemon are in
 * memory. What is proved here is the contract: raw bytes only, no owner to name,
 * no digest or object key in an answer, metadata stripped before it is stored,
 * and one generic refusal for every file the pipeline will not take.
 */

const UNAUTHORIZED = { statusCode: 401, message: 'Unauthorized' } as const;
const BAD_REQUEST = { statusCode: 400, message: 'Bad Request' } as const;
const PAYLOAD_TOO_LARGE = { statusCode: 413, message: 'Payload Too Large' } as const;
const UNSUPPORTED_MEDIA_TYPE = { statusCode: 415, message: 'Unsupported Media Type' } as const;
const UNPROCESSABLE_ENTITY = { statusCode: 422, message: 'Unprocessable Entity' } as const;
const SERVICE_UNAVAILABLE = { statusCode: 503, message: 'Service Unavailable' } as const;

const PNG = buildPng({ chunks: [TEXT_CHUNK] });
/** The comment text, so "the metadata is gone" can be checked by its bytes. */
const JPEG_COMMENT = Buffer.from('test-only comment', 'latin1');
const JPEG = buildJpeg({ segments: [COMMENT_SEGMENT] });
/** An executable stub: the magic of a PE file, nowhere near an image. */
const EXECUTABLE = Buffer.concat([Buffer.from('MZ', 'latin1'), Buffer.alloc(MIN_UPLOAD_BYTES, 0)]);
const HTML = Buffer.from(`<html><body>${'x'.repeat(256)}</body></html>`, 'latin1');
/** The four fields an upload answer may carry, and nothing else. */
const VIEW_FIELDS = ['contentType', 'id', 'kind', 'sizeBytes'];

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** A store that records every call, so "nothing was written" is a real assertion. */
class CountingStorage implements DocumentStorage {
  private readonly inner = new InMemoryDocumentStorage();
  readonly puts: string[] = [];
  readonly deletes: string[] = [];

  async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.puts.push(objectKey);

    await this.inner.put(objectKey, bytes);
  }

  async get(objectKey: string): Promise<Buffer> {
    return this.inner.get(objectKey);
  }

  async delete(objectKey: string): Promise<void> {
    this.deletes.push(objectKey);

    await this.inner.delete(objectKey);
  }

  async exists(objectKey: string): Promise<boolean> {
    return this.inner.exists(objectKey);
  }
}

/** Admits every other route, refuses the upload scope, and keeps the inputs. */
class RefusingUploadLimit {
  readonly consumed: ConsumeRateLimitInput[] = [];

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    this.consumed.push(input);

    return input.scope === 'document-upload'
      ? { allowed: false, remaining: 0, retryAfterSeconds: 30 }
      : { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
}

describe('Document upload route (e2e)', () => {
  const documents = new InMemoryIdentityDocuments();
  const storage = new CountingStorage();
  const scanner = new FakeVirusScanner();
  let harness: DocumentHarness;

  /** A fresh account per test: its own quota, its own rows. */
  const newAthlete = (): Promise<AdminAccount> => harness.signUp(Role.ATHLETE);

  const rowsOf = (account: AdminAccount) =>
    documents.rows.filter((row) => row.ownerUserId === account.userId);

  beforeAll(async () => {
    harness = await createDocumentHarness('documents', { documents, storage, scanner });
  });

  afterAll(async () => {
    await harness.close();
  });

  it('refuses the upload without a token, and writes nothing', async () => {
    const response = await harness.upload({ body: PNG, contentType: 'image/png' });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    expect(storage.puts).toEqual([]);
    expect(documents.rows).toEqual([]);
  });

  it('stores a JPEG for the token owner and answers only the four view fields', async () => {
    const account = await newAthlete();
    const puts = storage.puts.length;

    const response = await harness.upload({
      token: account.token,
      query: 'kind=MEDAL',
      body: JPEG,
      contentType: 'image/jpeg',
    });

    expect(response.status).toBe(201);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(Object.keys(response.body as object).sort()).toEqual(VIEW_FIELDS);
    expect(response.body).toMatchObject({ kind: 'MEDAL', contentType: 'image/jpeg' });

    const [row] = rowsOf(account);

    expect(rowsOf(account)).toHaveLength(1);
    expect(row).toMatchObject({
      ownerUserId: account.userId,
      kind: 'MEDAL',
      contentType: 'image/jpeg',
      status: 'ACTIVE',
    });
    expect(row?.id).toBe((response.body as { id: string }).id);
    expect(row?.sizeBytes).toBe((response.body as { sizeBytes: number }).sizeBytes);

    // One object, under the key the row names, holding ciphertext rather than the file.
    expect(storage.puts).toHaveLength(puts + 1);
    expect(storage.puts[storage.puts.length - 1]).toBe(row?.objectKey);

    const plaintext = await harness.decryptStored(row!);

    expect(plaintext.length).toBe(row?.sizeBytes);
    expect(sha256(plaintext)).toBe(row?.sha256);
    expect(plaintext.equals(JPEG)).toBe(false);
    // The comment segment the fixture carried is gone, so what is stored is sanitized.
    expect(JPEG.includes(JPEG_COMMENT)).toBe(true);
    expect(plaintext.includes(JPEG_COMMENT)).toBe(false);
    // Nothing that would locate or fingerprint the object leaves the server.
    expect(JSON.stringify(response.body)).not.toContain(row?.objectKey);
    expect(JSON.stringify(response.body)).not.toContain(row?.sha256);
  });

  it('records one audit entry about the document, with names and numbers only', async () => {
    const account = await newAthlete();

    const response = await harness.upload({
      token: account.token,
      query: 'kind=CERTIFICATE',
      body: PNG,
      contentType: 'image/png',
    });

    expect(response.status).toBe(201);

    const [row] = rowsOf(account);
    const entries = harness.rows(DOCUMENT_AUDIT_ACTIONS.UPLOADED, row?.id);

    expect(entries).toHaveLength(1);
    expect(entries[0]?.actorId).toBe(account.userId);
    expect(Object.keys(entries[0]?.metadata ?? {}).sort()).toEqual([
      'contentType',
      'documentId',
      'kind',
      'sizeBytes',
    ]);
    expect(entries[0]?.metadata).toEqual({
      documentId: row?.id,
      kind: 'CERTIFICATE',
      contentType: 'image/png',
      sizeBytes: row?.sizeBytes,
    });
  });

  it('strips the metadata before storing, and scans exactly what it stores', async () => {
    const account = await newAthlete();
    const scans = scanner.received.length;

    const response = await harness.upload({
      token: account.token,
      body: PNG,
      contentType: 'image/png',
    });

    expect(response.status).toBe(201);
    expect(pngChunks(PNG).map((chunk) => chunk.type)).toContain('tEXt');

    const plaintext = await harness.decryptStored(rowsOf(account)[0]!);

    expect(pngChunks(plaintext).map((chunk) => chunk.type)).not.toContain('tEXt');
    expect(scanner.received).toHaveLength(scans + 1);
    expect(scanner.received[scanner.received.length - 1]?.equals(plaintext)).toBe(true);
  });

  it('refuses a body whose media type is not one of the two this route takes', async () => {
    const account = await newAthlete();
    const puts = storage.puts.length;
    const scans = scanner.received.length;

    const refused: ReadonlyArray<readonly [string, Buffer | string]> = [
      ['text/plain; charset=utf-8', 'hello there'],
      ['application/json', JSON.stringify({ kind: 'NATIONAL_ID' })],
      ['application/x-www-form-urlencoded', 'kind=NATIONAL_ID'],
      ['application/octet-stream', PNG],
      ['multipart/form-data; boundary=x', '--x--'],
      ['image/gif', PNG],
    ];

    for (const [contentType, body] of refused) {
      const response = await harness.upload({ token: account.token, body, contentType });

      expect(response.status).toBe(415);
      expect(response.body).toEqual({ ...UNSUPPORTED_MEDIA_TYPE, requestId: expect.any(String) });
    }

    // No media type at all is the same refusal, and none of it was buffered.
    const bare = await harness.upload({ token: account.token, body: PNG });

    expect(bare.status).toBe(415);
    expect(bare.body).toEqual({ ...UNSUPPORTED_MEDIA_TYPE, requestId: expect.any(String) });
    expect(storage.puts).toHaveLength(puts);
    expect(scanner.received).toHaveLength(scans);
    expect(rowsOf(account)).toEqual([]);
  });

  it('answers one generic 422 for every file the pipeline will not take', async () => {
    const account = await newAthlete();
    const puts = storage.puts.length;
    const scans = scanner.received.length;

    const refused = [
      // An executable and a web page, renamed to an image.
      EXECUTABLE,
      HTML,
      // Cut short inside the header, and a body below the floor.
      truncatedTo(PNG, MIN_UPLOAD_BYTES - 1),
      Buffer.alloc(MIN_UPLOAD_BYTES - 1),
      // A valid image with bytes appended after its end marker.
      withTrailingBytes(PNG, Buffer.from('appended', 'latin1')),
    ];

    for (const body of refused) {
      const response = await harness.upload({
        token: account.token,
        body,
        contentType: 'image/png',
      });

      expect(response.status).toBe(422);
      expect(response.body).toEqual({ ...UNPROCESSABLE_ENTITY, requestId: expect.any(String) });
    }

    // An empty body stops at the controller, with the same generic answer.
    const empty = await harness.upload({
      token: account.token,
      body: Buffer.alloc(0),
      contentType: 'image/png',
    });

    expect(empty.status).toBe(422);
    expect(empty.body).toEqual({ ...UNPROCESSABLE_ENTITY, requestId: expect.any(String) });
    // Nothing was scanned, stored or written, and no caller learned which check failed.
    expect(storage.puts).toHaveLength(puts);
    expect(scanner.received).toHaveLength(scans);
    expect(rowsOf(account)).toEqual([]);
  });

  it('refuses a request that names no kind, or a kind this route does not take', async () => {
    const account = await newAthlete();
    const puts = storage.puts.length;

    const refused = [
      '', // no query string at all
      'kind=',
      'kind=PASSPORT',
      'kind=national_id',
      'kind=UNKNOWN',
      'kind=NATIONAL_ID&kind=MEDAL',
      // The owner is the token, so a parameter trying to name one is refused.
      'kind=NATIONAL_ID&ownerUserId=someone-else',
      'kind=NATIONAL_ID&objectKey=someone-elses-key',
    ];

    for (const query of refused) {
      const response = await harness.upload({
        token: account.token,
        query,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    }

    expect(storage.puts).toHaveLength(puts);
    expect(rowsOf(account)).toEqual([]);
  });

  it('accepts every kind the DocumentKind enum declares, and refuses any other', async () => {
    // Exactly the enum the column is created from, value by value.
    for (const kind of Object.values(DocumentKind)) {
      const account = await newAthlete();

      const response = await harness.upload({
        token: account.token,
        query: `kind=${kind}`,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(201);
      expect((response.body as { kind: string }).kind).toBe(kind);
      expect(rowsOf(account)).toHaveLength(1);
      expect(rowsOf(account)[0]?.kind).toBe(kind);
    }

    // A kind the enum does not have stops at the pipe, before a byte is read.
    const account = await newAthlete();
    const puts = storage.puts.length;
    const refused = await harness.upload({
      token: account.token,
      query: 'kind=PASSPORT',
      body: PNG,
      contentType: 'image/png',
    });

    expect(refused.status).toBe(400);
    expect(refused.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(storage.puts).toHaveLength(puts);
    expect(rowsOf(account)).toEqual([]);
  });

  it('files the document under the token owner, whatever a header claims', async () => {
    const owner = await newAthlete();
    const other = await newAthlete();

    const response = await harness.upload({
      token: owner.token,
      body: PNG,
      contentType: 'image/png',
      headers: { 'x-user-id': other.userId, 'x-owner-id': other.userId },
    });

    expect(response.status).toBe(201);
    expect(rowsOf(owner)).toHaveLength(1);
    expect(rowsOf(other)).toEqual([]);
  });

  it('refuses the upload once the account already holds its quota', async () => {
    const account = await newAthlete();

    documents.seedActive(account.userId, MAX_ACTIVE_DOCUMENTS - 1);

    const last = await harness.upload({
      token: account.token,
      body: PNG,
      contentType: 'image/png',
    });

    expect(last.status).toBe(201);
    expect(rowsOf(account)).toHaveLength(MAX_ACTIVE_DOCUMENTS);

    const puts = storage.puts.length;
    const refused = await harness.upload({
      token: account.token,
      body: PNG,
      contentType: 'image/png',
    });

    // A full account looks exactly like a rejected file from the outside.
    expect(refused.status).toBe(422);
    expect(refused.body).toEqual({ ...UNPROCESSABLE_ENTITY, requestId: expect.any(String) });
    expect(rowsOf(account)).toHaveLength(MAX_ACTIVE_DOCUMENTS);
    expect(storage.puts).toHaveLength(puts);
  });

  it('takes a body far over the JSON limit, and refuses one over the upload limit', async () => {
    const account = await newAthlete();
    // A real image with a payload no 1 KiB parser would ever have accepted.
    const big = buildPng({ chunks: [{ type: 'IDAT', data: Buffer.alloc(4_096, 1) }] });

    // The raw parser on this path is the only one that reads this much.
    expect(big.length).toBeGreaterThan(Number(TEST_ENV.BODY_LIMIT_BYTES));

    const accepted = await harness.upload({
      token: account.token,
      body: big,
      contentType: 'image/png',
    });

    expect(accepted.status).toBe(201);
    expect((accepted.body as { sizeBytes: number }).sizeBytes).toBeGreaterThan(
      Number(TEST_ENV.BODY_LIMIT_BYTES),
    );

    const puts = storage.puts.length;
    const scans = scanner.received.length;
    const oversized = await harness.upload({
      token: account.token,
      body: Buffer.alloc(MAX_UPLOAD_BYTES + 1, 0x2f),
      contentType: 'image/png',
    });

    expect(oversized.status).toBe(413);
    expect(oversized.body).toEqual({ ...PAYLOAD_TOO_LARGE, requestId: expect.any(String) });
    expect(storage.puts).toHaveLength(puts);
    expect(scanner.received).toHaveLength(scans);

    // The global limit is untouched: every other route still stops at 1 KiB.
    const json = await harness.post('/auth/login', undefined, { proof: 'x'.repeat(2_000) });

    expect(json.status).toBe(413);
    expect(json.body).toEqual({ ...PAYLOAD_TOO_LARGE, requestId: expect.any(String) });
  });
});

/**
 * The upload counters, over the real route: the limiter refuses the scope, and
 * the answer is the shared 429 envelope with the same `Retry-After` every other
 * limited route sends.
 */
describe('Document upload limits (e2e)', () => {
  it('answers 429 for the upload scope and never reaches the pipeline', async () => {
    const limiter = new RefusingUploadLimit();
    const documents = new InMemoryIdentityDocuments();
    const storage = new CountingStorage();
    const harness = await createDocumentHarness('documents_limited', {
      documents,
      storage,
      scanner: new FakeVirusScanner(),
      rateLimit: limiter as unknown as RateLimitService,
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const response = await harness.upload({
        token: account.token,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(429);
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: expect.any(String),
      });
      expect(response.headers['retry-after']).toBe('30');

      // Per user, in the upload's own scope, burst window first.
      const charged = limiter.consumed.filter((input) => input.scope === 'document-upload');

      expect(charged).toEqual([
        {
          scope: 'document-upload',
          identifier: account.userId,
          limit: 3,
          windowSeconds: 60,
        },
      ]);
      expect(storage.puts).toEqual([]);
      expect(documents.rows).toEqual([]);
    } finally {
      await harness.close();
    }
  });
});

/**
 * A deployment that has not configured one of the three pieces the route needs.
 *
 * It still boots - a development machine has no bucket and no daemon - and every
 * upload fails closed: a generic 503 for the parts the service owns, the
 * pipeline's generic 422 for the scanner, and never a row or an object.
 */
describe('Document upload with an unconfigured pipeline (e2e)', () => {
  it('answers 503 and stores nothing when there is no master key', async () => {
    const documents = new InMemoryIdentityDocuments();
    const storage = new CountingStorage();
    const harness = await createDocumentHarness('documents_nokey', {
      documents,
      storage,
      scanner: new FakeVirusScanner(),
      env: { DOCUMENT_MASTER_KEY: undefined },
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const response = await harness.upload({
        token: account.token,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(503);
      expect(response.body).toEqual({ ...SERVICE_UNAVAILABLE, requestId: expect.any(String) });
      expect(response.headers['cache-control']).toBe('no-store');
      // The scan ran, then the encryption failed: nothing was written anywhere.
      expect(storage.puts).toEqual([]);
      expect(documents.rows).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  it('answers 503 and writes no row when no bucket is configured', async () => {
    const documents = new InMemoryIdentityDocuments();
    const harness = await createAdminHarness('documents_nobucket', {
      identityDocumentRepository: documents,
      virusScanner: new FakeVirusScanner(),
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const response = await uploadTo(harness.app, {
        token: account.token,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(503);
      expect(response.body).toEqual({ ...SERVICE_UNAVAILABLE, requestId: expect.any(String) });
      expect(documents.rows).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  it('answers the pipeline 422 and stores nothing when no scanner is configured', async () => {
    const documents = new InMemoryIdentityDocuments();
    const storage = new CountingStorage();
    const harness = await createAdminHarness('documents_noscanner', {
      identityDocumentRepository: documents,
      documentStorage: storage,
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const response = await uploadTo(harness.app, {
        token: account.token,
        body: PNG,
        contentType: 'image/png',
      });

      expect(response.status).toBe(422);
      expect(response.body).toEqual({ ...UNPROCESSABLE_ENTITY, requestId: expect.any(String) });
      expect(storage.puts).toEqual([]);
      expect(documents.rows).toEqual([]);
    } finally {
      await harness.close();
    }
  });
});
