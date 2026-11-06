import { ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { createHash } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import type { PrismaService } from '../../database/prisma.service';
import { DocumentCryptoService, type EncryptedDocument } from '../document-crypto.service';
import { EnvKeyWrapper } from '../env-key-wrapper';
import { InMemoryDocumentStorage } from '../in-memory-document-storage';
import { DocumentIngestService } from '../ingest/document-ingest.service';
import { DocumentIngestError } from '../ingest/ingest.errors';
import { buildPng, TEXT_CHUNK } from '../ingest/testing/image-fixtures';
import { FakeVirusScanner } from '../ingest/testing/fake-virus-scanner';
import {
  DocumentUploadService,
  MAX_ACTIVE_DOCUMENTS,
  type DocumentUploadRequest,
} from './document-upload.service';
import type { IdentityDocumentRecord } from './identity-document.repository';
import { InMemoryIdentityDocuments } from './testing/in-memory-identity-documents';

/** Fixed, fake master key: base64 of exactly 32 bytes. */
const MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_ID = '44444444-4444-4444-8444-444444444444';
const OTHER_KEY = '5f2c9a71-4d63-4b8e-9c05-7a1e2d3f4b60';
/** A comment chunk, so the sanitizer has something to strip and something to prove. */
const COMMENT = Buffer.from('test-only photo', 'latin1');

const PNG = buildPng({ chunks: [TEXT_CHUNK] });

const actor: PolicySubject = { id: USER_ID, role: Role.ATHLETE };

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** The order the steps ran in, shared by every fake in one test. */
class Timeline {
  readonly events: string[] = [];

  mark(event: string): void {
    this.events.push(event);
  }
}

class RecordingDocuments extends InMemoryIdentityDocuments {
  failInsert = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async countActiveByOwner(
    ownerUserId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    this.timeline.mark('count');

    return super.countActiveByOwner(ownerUserId, tx);
  }

  override async insert(
    record: Parameters<InMemoryIdentityDocuments['insert']>[0],
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord> {
    this.timeline.mark('insert');

    if (this.failInsert) {
      this.failInsert = false;

      throw new Error('database is unavailable');
    }

    return super.insert(record, tx);
  }
}

class RecordingStorage extends InMemoryDocumentStorage {
  readonly puts: string[] = [];
  readonly deletes: string[] = [];
  failPut = false;
  failDelete = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.timeline.mark('put');
    this.puts.push(objectKey);

    if (this.failPut) throw new Error('storage is unavailable');

    await super.put(objectKey, bytes);
  }

  override async delete(objectKey: string): Promise<void> {
    this.timeline.mark('delete');
    this.deletes.push(objectKey);

    if (this.failDelete) throw new Error('storage is unavailable');

    await super.delete(objectKey);
  }
}

class RecordingScanner extends FakeVirusScanner {
  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async scan(bytes: Buffer): Promise<void> {
    this.timeline.mark('scan');

    await super.scan(bytes);
  }
}

class RecordingCrypto extends DocumentCryptoService {
  fail = false;

  constructor(private readonly timeline: Timeline) {
    super(new EnvKeyWrapper({ masterKey: MASTER_KEY }));
  }

  override async encrypt(plaintext: Buffer, aad: string): Promise<EncryptedDocument> {
    this.timeline.mark('encrypt');

    if (this.fail) throw new Error('key service is unavailable');

    return super.encrypt(plaintext, aad);
  }
}

class RecordingAudit extends FakeAudit {
  fail = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    this.timeline.mark('audit');

    await super.record(entry, tx);

    if (this.fail) throw new Error('audit chain is unavailable');
  }
}

/**
 * The one thing the service needs from Prisma: an interactive transaction. A
 * throw from the callback discards what the callback wrote, the way the real
 * client does, so a rolled-back upload can be checked for a real rollback.
 */
class FakePrisma {
  readonly transactions: Prisma.TransactionClient[] = [];
  readonly options: unknown[] = [];

  constructor(private readonly documents: RecordingDocuments) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    // A plain marker: the fakes ignore the client and only have to agree on it.
    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;

    this.transactions.push(tx);
    this.options.push(options);

    const before = this.documents.snapshot();

    try {
      return await run(tx);
    } catch (error) {
      this.documents.restore(before);

      throw error;
    }
  }
}

class QuietLogger {
  readonly warns: { payload: unknown; message: unknown }[] = [];

  warn(payload: unknown, message?: unknown): void {
    this.warns.push({ payload, message });
  }
}

function createService() {
  const timeline = new Timeline();
  const documents = new RecordingDocuments(timeline);
  const storage = new RecordingStorage(timeline);
  const scanner = new RecordingScanner(timeline);
  const audit = new RecordingAudit(timeline);
  const crypto = new RecordingCrypto(timeline);
  const logger = new QuietLogger();
  const prisma = new FakePrisma(documents);
  const service = new DocumentUploadService(
    prisma as unknown as PrismaService,
    documents,
    new DocumentIngestService(scanner),
    crypto,
    storage,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, timeline, documents, storage, scanner, audit, crypto, logger, prisma };
}

function upload(
  service: DocumentUploadService,
  overrides: Partial<DocumentUploadRequest> = {},
): Promise<{ id: string; kind: string; contentType: string; sizeBytes: number }> {
  return service.upload(actor, { kind: 'NATIONAL_ID', bytes: PNG, ...overrides });
}

/** The single row the upload wrote, or a failure that names what went wrong. */
function onlyRow(documents: InMemoryIdentityDocuments): IdentityDocumentRecord {
  const rows = documents.rows;

  expect(rows).toHaveLength(1);

  return rows[0] as IdentityDocumentRecord;
}

describe('DocumentUploadService', () => {
  it('stores ciphertext under a random key and returns five fields', async () => {
    const { service, documents, storage, scanner, crypto, timeline, prisma, audit } =
      createService();

    const view = await upload(service);
    const row = onlyRow(documents);
    const sanitized = scanner.received[0] as Buffer;

    // The order is the contract, and this is the happy path of it.
    expect(timeline.events).toEqual(['count', 'scan', 'encrypt', 'put', 'insert', 'audit']);

    // What the caller gets, and nothing else.
    expect(Object.keys(view).sort()).toEqual(['contentType', 'id', 'kind', 'sizeBytes']);
    expect(view).toEqual({
      id: row.id,
      kind: 'NATIONAL_ID',
      contentType: 'image/png',
      sizeBytes: sanitized.length,
    });
    expect(JSON.stringify(view)).not.toContain(row.objectKey);
    expect(JSON.stringify(view)).not.toContain(row.sha256);
    expect(JSON.stringify(view)).not.toContain(row.wrappedDek.toString('base64'));

    // The row describes the sanitized bytes, not the upload.
    expect(row).toMatchObject({
      ownerUserId: USER_ID,
      kind: 'NATIONAL_ID',
      contentType: 'image/png',
      status: 'ACTIVE',
      deletedAt: null,
    });
    expect(row.sizeBytes).toBe(sanitized.length);
    expect(row.sha256).toBe(sha256(sanitized));
    expect(row.keyId).toBe('v1');
    expect(row.iv).toHaveLength(12);
    expect(row.authTag).toHaveLength(16);
    expect(row.objectKey).not.toContain(USER_ID);
    expect(scanner.received[0]?.equals(PNG)).toBe(false);
    expect(sanitized.includes(COMMENT)).toBe(false);

    // Only ciphertext is stored, and it reads back only under its own key.
    const stored = await storage.get(row.objectKey);

    expect(stored.includes(COMMENT)).toBe(false);
    expect(stored.includes(Buffer.from([0x89, 0x50, 0x4e, 0x47]))).toBe(false);
    expect(storage.puts).toEqual([row.objectKey]);
    expect(
      await crypto.decrypt(
        {
          ciphertext: stored,
          iv: row.iv,
          authTag: row.authTag,
          wrappedDek: row.wrappedDek,
          keyId: row.keyId,
        },
        row.objectKey,
      ),
    ).toEqual(sanitized);
    await expect(
      crypto.decrypt(
        {
          ciphertext: stored,
          iv: row.iv,
          authTag: row.authTag,
          wrappedDek: row.wrappedDek,
          keyId: row.keyId,
        },
        OTHER_KEY,
      ),
    ).rejects.toThrow('document unreadable');

    // The row and its trail share one unit of work.
    expect(documents.transactions).toEqual([prisma.transactions[0]]);
    expect(audit.transactions).toEqual([prisma.transactions[0]]);
    expect(prisma.options).toEqual([{ maxWait: 5_000, timeout: 10_000 }]);
  });

  it('audits the upload with names and numbers only', async () => {
    const { service, documents, audit } = createService();

    const view = await upload(service, { kind: 'CERTIFICATE' });

    expect(audit.records).toHaveLength(1);

    const entry = audit.records[0] as AuditRecord;
    const row = onlyRow(documents);

    // Exactly these keys: no request id or ip is invented where there is none.
    expect(Object.keys(entry).sort()).toEqual([
      'action',
      'actorId',
      'actorRole',
      'metadata',
      'targetId',
      'targetType',
    ]);
    expect(entry).toMatchObject({
      action: 'document.uploaded',
      actorId: USER_ID,
      actorRole: 'ATHLETE',
      targetType: 'identity_document',
      targetId: view.id,
    });
    expect(entry.metadata).toEqual({
      documentId: view.id,
      kind: 'CERTIFICATE',
      contentType: 'image/png',
      sizeBytes: row.sizeBytes,
    });
    expect(JSON.stringify(entry)).not.toContain(row.objectKey);
    expect(JSON.stringify(entry)).not.toContain(row.sha256);
    expect(JSON.stringify(entry)).not.toContain(COMMENT.toString('latin1'));
  });

  it.each([Role.USER, Role.ATHLETE, Role.ADMIN, Role.OWNER])(
    'writes the row for the caller and nobody else (%s)',
    async (role) => {
      const { service, documents } = createService();

      await service.upload({ id: OTHER_ID, role }, { kind: 'MEDAL', bytes: PNG });

      expect(documents.counts).toEqual([OTHER_ID]);
      expect(onlyRow(documents).ownerUserId).toBe(OTHER_ID);
    },
  );

  it('refuses the eleventh document before scanning, encrypting or storing', async () => {
    const { service, documents, storage, scanner, audit, prisma } = createService();

    documents.seedActive(USER_ID, MAX_ACTIVE_DOCUMENTS);

    await expect(upload(service)).rejects.toBeInstanceOf(DocumentIngestError);

    expect(documents.counts).toEqual([USER_ID]);
    expect(scanner.received).toEqual([]);
    expect(storage.puts).toEqual([]);
    expect(storage.deletes).toEqual([]);
    expect(documents.inserts).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toEqual([]);
  });

  it('accepts the tenth document', async () => {
    const { service, documents } = createService();

    documents.seedActive(USER_ID, MAX_ACTIVE_DOCUMENTS - 1);

    await upload(service);

    expect(documents.rows).toHaveLength(MAX_ACTIVE_DOCUMENTS);
  });

  it('counts only the caller documents', async () => {
    const { service, documents } = createService();

    documents.seedActive(OTHER_ID, MAX_ACTIVE_DOCUMENTS);

    await upload(service);

    // Somebody else's ten documents are not the caller's quota.
    expect(documents.rows.filter((row) => row.ownerUserId === USER_ID)).toHaveLength(1);
  });

  it('stores nothing when the scanner refuses the file', async () => {
    const { service, documents, storage, scanner, audit, prisma } = createService();

    scanner.behave('infected');

    await expect(upload(service)).rejects.toBeInstanceOf(DocumentIngestError);

    expect(storage.puts).toEqual([]);
    expect(storage.deletes).toEqual([]);
    expect(documents.inserts).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toEqual([]);
  });

  it('refuses a file whose declared type contradicts its bytes', async () => {
    const { service, documents, storage, scanner } = createService();

    await expect(
      upload(service, { claimedMime: 'image/jpeg', claimedExtension: 'jpg' }),
    ).rejects.toBeInstanceOf(DocumentIngestError);

    expect(scanner.received).toEqual([]);
    expect(storage.puts).toEqual([]);
    expect(documents.inserts).toEqual([]);
  });

  it('writes no row when the object store refuses the ciphertext', async () => {
    const { service, documents, storage, audit, prisma } = createService();

    storage.failPut = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(storage.puts).toHaveLength(1);
    expect(await storage.exists(storage.puts[0] as string)).toBe(false);
    expect(storage.deletes).toEqual([]);
    expect(documents.inserts).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toEqual([]);
  });

  it('stores nothing when the key service refuses to wrap', async () => {
    const { service, documents, storage, audit, prisma, crypto } = createService();

    crypto.fail = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(storage.puts).toEqual([]);
    expect(documents.inserts).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toEqual([]);
  });

  it('removes the blob again when the row cannot be written', async () => {
    const { service, documents, storage, audit, logger, timeline, prisma } = createService();

    documents.failInsert = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    const [objectKey] = storage.puts;

    expect(timeline.events).toEqual(['count', 'scan', 'encrypt', 'put', 'insert', 'delete']);
    expect(storage.deletes).toEqual([objectKey]);
    expect(await storage.exists(objectKey as string)).toBe(false);
    expect(documents.rows).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toHaveLength(1);
    expect(logger.warns).toEqual([
      {
        payload: { action: 'document.uploaded', stage: 'persist' },
        message: 'document upload rolled back',
      },
    ]);
  });

  it('rolls the row back and removes the blob when the trail cannot be written', async () => {
    const { service, documents, storage, audit, timeline } = createService();

    audit.fail = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    const [objectKey] = storage.puts;

    // The insert ran, then the audit entry failed, then the blob was removed.
    expect(timeline.events).toEqual([
      'count',
      'scan',
      'encrypt',
      'put',
      'insert',
      'audit',
      'delete',
    ]);
    expect(documents.inserts).toHaveLength(1);
    expect(documents.rows).toEqual([]);
    expect(audit.records).toHaveLength(1);
    expect(storage.deletes).toEqual([objectKey]);
    expect(await storage.exists(objectKey as string)).toBe(false);
  });

  it('reports the same generic failure when the cleanup fails too', async () => {
    const { service, documents, storage } = createService();

    documents.failInsert = true;
    storage.failDelete = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(documents.rows).toEqual([]);
  });
});
