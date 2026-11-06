import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { DocumentCryptoService } from '../../src/documents/document-crypto.service';
import type { DocumentStorage } from '../../src/documents/document-storage';
import { EnvKeyWrapper } from '../../src/documents/env-key-wrapper';
import { InMemoryDocumentStorage } from '../../src/documents/in-memory-document-storage';
import { FakeVirusScanner } from '../../src/documents/ingest/testing/fake-virus-scanner';
import type { VirusScanner } from '../../src/documents/ingest/virus-scanner';
import type { IdentityDocumentRecord } from '../../src/documents/records/identity-document.repository';
import { InMemoryIdentityDocuments } from '../../src/documents/records/testing/in-memory-identity-documents';
import type { RateLimitService } from '../../src/rate-limit/rate-limit.service';
import { createAdminHarness } from './admin-harness';
import { TEST_ENV, type TestEnvOverrides } from './test-env';

export interface DocumentHarnessOptions {
  /** Environment overrides, e.g. to remove the master key. */
  readonly env?: TestEnvOverrides;
  /** In-memory rows; share one to inspect what the route wrote. */
  readonly documents?: InMemoryIdentityDocuments;
  /** Any store, including one that fails, to prove the route fails closed. */
  readonly storage?: DocumentStorage;
  /** A fake daemon answer; defaults to "clean". */
  readonly scanner?: VirusScanner;
  /** The limiter behind every route, e.g. one that refuses the upload scope. */
  readonly rateLimit?: RateLimitService;
}

export interface UploadInput {
  /** The caller's access token; omitted entirely for the unauthenticated case. */
  readonly token?: string;
  /** Raw query string, so a test can send one this API does not accept. */
  readonly query?: string;
  /** The request body, sent as the raw bytes it is. */
  readonly body: Buffer | string;
  /** Set to the declared media type; omitted, no header is sent at all. */
  readonly contentType?: string;
  /** Extra headers, e.g. an owner id a client might hope the server trusts. */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * `POST /athlete/documents` with the file as the raw body, against any built
 * application - the harness below and the fail-closed suites both use it.
 */
export function uploadTo(app: INestApplication, input: UploadInput) {
  const call = request(app.getHttpServer()).post(
    `/athlete/documents?${input.query ?? 'kind=NATIONAL_ID'}`,
  );
  const authorized =
    input.token === undefined ? call : call.set('Authorization', `Bearer ${input.token}`);
  const typed =
    input.contentType === undefined
      ? authorized
      : authorized.set('Content-Type', input.contentType);

  for (const [name, value] of Object.entries(input.headers ?? {})) typed.set(name, value);

  return typed.send(input.body);
}

/**
 * The fixture the document upload suite shares: the real application over an
 * in-memory document table, an in-memory bucket and a fake scanner, so no suite
 * needs PostgreSQL, S3, clamd or Redis.
 *
 * The envelope key is the test one from `TEST_ENV`, so `decryptStored` opens what
 * the route wrote with exactly the material the row carries.
 */
export async function createDocumentHarness(
  prefix = 'document',
  options: DocumentHarnessOptions = {},
) {
  const documents = options.documents ?? new InMemoryIdentityDocuments();
  const storage = options.storage ?? new InMemoryDocumentStorage();
  const scanner = options.scanner ?? new FakeVirusScanner();

  const base = await createAdminHarness(
    prefix,
    {
      identityDocumentRepository: documents,
      documentStorage: storage,
      virusScanner: scanner,
      // Omitted rather than set to undefined, so the harness default survives.
      ...(options.rateLimit === undefined ? {} : { rateLimit: options.rateLimit }),
    },
    options.env ?? {},
  );

  const crypto = new DocumentCryptoService(
    new EnvKeyWrapper({ masterKey: TEST_ENV.DOCUMENT_MASTER_KEY }),
  );

  const upload = (input: UploadInput) => uploadTo(base.app, input);

  /**
   * Decrypts what the row points at, using the row's own key id, envelope and the
   * object key as AAD - the same material a read path would have.
   */
  function decryptStored(record: IdentityDocumentRecord): Promise<Buffer> {
    return storage.get(record.objectKey).then((ciphertext) =>
      crypto.decrypt(
        {
          ciphertext,
          iv: record.iv,
          authTag: record.authTag,
          wrappedDek: record.wrappedDek,
          keyId: record.keyId,
        },
        record.objectKey,
      ),
    );
  }

  return { ...base, documents, storage, scanner, upload, decryptStored };
}

export type DocumentHarness = Awaited<ReturnType<typeof createDocumentHarness>>;
