import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import {
  FakeAudit,
  FakeLogger,
  type AuditRecord,
} from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import type { PrismaService } from '../../database/prisma.service';
import { DOCUMENT_AUDIT_ACTIONS } from './document-upload.service';
import type { IdentityDocumentRecord } from './identity-document.repository';
import { MAX_LISTED_DOCUMENTS, OwnerDocumentsService } from './owner-documents.service';
import { InMemoryIdentityDocuments } from './testing/in-memory-identity-documents';

/**
 * The owner list and delete, at the service boundary.
 *
 * The repository, the transaction and the trail are fakes, but the order and
 * the fail-closed rule are the real ones: the row and the audit entry share one
 * transaction, and a trail that cannot be written leaves the document ACTIVE.
 */

const OWNER: PolicySubject = Object.freeze({
  id: '11111111-1111-4111-8111-111111111111',
  role: Role.ATHLETE,
});
const OTHER: PolicySubject = Object.freeze({
  id: '22222222-2222-4222-8222-222222222222',
  role: Role.ATHLETE,
});
const MISSING_ID = '33333333-3333-4333-8333-333333333333';

/** The five fields a list item may carry, and nothing else. */
const SUMMARY_FIELDS = ['contentType', 'createdAt', 'id', 'kind', 'sizeBytes'];

/** A trail that can be made to fail after it stored the entry, like a broken chain. */
class FailingAudit extends FakeAudit {
  fail = false;

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    await super.record(entry, tx);

    if (this.fail) throw new Error('audit chain is unavailable');
  }
}

/** A repository that cannot list, for the fail-closed answer. */
class UnlistableDocuments extends InMemoryIdentityDocuments {
  override async listActiveByOwner(): Promise<IdentityDocumentRecord[]> {
    throw new Error('database is unavailable');
  }
}

/** A repository that cannot delete, for the fail-closed answer. */
class UndeletableDocuments extends InMemoryIdentityDocuments {
  override async softDeleteOwnedActive(): Promise<IdentityDocumentRecord | null> {
    throw new Error('database is unavailable');
  }
}

/**
 * The one thing the service needs from Prisma: an interactive transaction. A
 * throw from the callback restores what the callback wrote, the way the real
 * client discards it, so a rolled-back delete is a real rollback here.
 */
class FakePrisma {
  readonly transactions: Prisma.TransactionClient[] = [];
  readonly options: unknown[] = [];

  /** The review state the delete lock reads; `null` means the account has no profile. */
  reviewStatus: 'DRAFT' | 'PENDING' | 'APPROVED' | 'REJECTED' | null = null;

  readonly athleteProfile = {
    findUnique: (): Promise<{ reviewStatus: string } | null> =>
      Promise.resolve(this.reviewStatus === null ? null : { reviewStatus: this.reviewStatus }),
  };

  constructor(private readonly documents: InMemoryIdentityDocuments) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
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

function createHarness(documents: InMemoryIdentityDocuments = new InMemoryIdentityDocuments()) {
  const audit = new FailingAudit();
  const logger = new FakeLogger();
  const prisma = new FakePrisma(documents);
  const service = new OwnerDocumentsService(
    prisma as unknown as PrismaService,
    documents,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, documents, audit, logger, prisma };
}

/** The one row the harness must hold, or a failure that says what went wrong. */
function onlyRow(documents: InMemoryIdentityDocuments): IdentityDocumentRecord {
  const rows = documents.rows;

  expect(rows).toHaveLength(1);

  return rows[0] as IdentityDocumentRecord;
}

describe('OwnerDocumentsService.list', () => {
  it('returns the owner rows newest first, as the five allowed fields only', async () => {
    const { service, documents } = createHarness();

    const oldest = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));
    const newest = documents.seed(OWNER.id, new Date('2026-03-01T00:00:00.000Z'));
    const middle = documents.seed(OWNER.id, new Date('2026-02-01T00:00:00.000Z'));
    const foreign = documents.seed(OTHER.id, new Date('2026-04-01T00:00:00.000Z'));
    const gone = documents.seed(OWNER.id, new Date('2026-05-01T00:00:00.000Z'));

    documents.softDelete(gone.id);

    const list = await service.list(OWNER);

    expect(list.documents.map((row) => row.id)).toEqual([newest.id, middle.id, oldest.id]);
    expect(list.documents.map((row) => row.id)).not.toContain(foreign.id);
    expect(list.documents.map((row) => row.id)).not.toContain(gone.id);

    for (const item of list.documents) {
      expect(Object.keys(item).sort()).toEqual(SUMMARY_FIELDS);
      expect(item).not.toHaveProperty('objectKey');
      expect(item).not.toHaveProperty('sha256');
      expect(item).not.toHaveProperty('keyId');
      expect(item).not.toHaveProperty('wrappedDek');
      expect(item).not.toHaveProperty('iv');
      expect(item).not.toHaveProperty('authTag');
      expect(item).not.toHaveProperty('ownerUserId');
      expect(item).not.toHaveProperty('status');
      expect(item).not.toHaveProperty('deletedAt');
    }

    // The cap is applied by the repository call, and the owner is the principal.
    expect(documents.lists).toEqual([{ ownerUserId: OWNER.id, limit: MAX_LISTED_DOCUMENTS }]);
    expect(MAX_LISTED_DOCUMENTS).toBe(100);
  });

  it('answers an empty list for an account with no documents', async () => {
    const { service } = createHarness();

    await expect(service.list(OWNER)).resolves.toEqual({ documents: [] });
  });

  it('fails closed with a generic 503 when the repository cannot read', async () => {
    const { service, logger } = createHarness(new UnlistableDocuments());

    await expect(service.list(OWNER)).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(logger.warns).toEqual([{ action: 'document.list', stage: 'repository' }]);
  });
});

describe('OwnerDocumentsService.delete', () => {
  it('soft-deletes the row in one transaction with its audit entry', async () => {
    const { service, documents, audit, prisma } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'), 'MEDAL');

    await service.delete(OWNER, row.id);

    const stored = onlyRow(documents);

    expect(stored.status).toBe('DELETED');
    expect(stored.deletedAt).toBeInstanceOf(Date);
    expect(stored.deletedAt?.getTime()).toBeGreaterThanOrEqual(row.createdAt.getTime());

    // The row and the trail went through the same client.
    expect(documents.deletions).toEqual([{ documentId: row.id, ownerUserId: OWNER.id }]);
    expect(prisma.transactions).toHaveLength(1);
    expect(audit.transactions).toEqual(prisma.transactions);
    expect(audit.records).toEqual([
      expect.objectContaining({
        action: DOCUMENT_AUDIT_ACTIONS.DELETED,
        actorId: OWNER.id,
        actorRole: Role.ATHLETE,
        targetType: 'identity_document',
        targetId: row.id,
        metadata: { documentId: row.id, kind: 'MEDAL' },
      }),
    ]);

    // Nothing that would locate, fingerprint or decrypt the blob is recorded.
    const [entry] = audit.records;

    expect(Object.keys(entry?.metadata ?? {}).sort()).toEqual(['documentId', 'kind']);
    expect(JSON.stringify(entry?.metadata)).not.toContain(row.objectKey);
    expect(JSON.stringify(entry?.metadata)).not.toContain(row.sha256);
    expect(JSON.stringify(entry?.metadata)).not.toContain(row.keyId);
    expect(entry?.metadata).not.toHaveProperty('objectKey');
    expect(entry?.metadata).not.toHaveProperty('sizeBytes');
  });

  it('answers the same 404 for a missing id and writes no trail', async () => {
    const { service, documents, audit } = createHarness();

    await expect(service.delete(OWNER, MISSING_ID)).rejects.toBeInstanceOf(NotFoundException);
    expect(documents.rows).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('refuses a foreign document with the same 404 and leaves it ACTIVE', async () => {
    const { service, documents, audit } = createHarness();
    const foreign = documents.seed(OTHER.id, new Date('2026-01-01T00:00:00.000Z'));

    await expect(service.delete(OWNER, foreign.id)).rejects.toBeInstanceOf(NotFoundException);
    expect(documents.rows[0]?.status).toBe('ACTIVE');
    expect(audit.records).toEqual([]);
  });

  it('refuses an already deleted document with the same 404', async () => {
    const { service, documents, audit } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));

    documents.softDelete(row.id);

    const deletedAt = documents.rows[0]?.deletedAt;

    await expect(service.delete(OWNER, row.id)).rejects.toBeInstanceOf(NotFoundException);
    expect(documents.rows[0]?.status).toBe('DELETED');
    expect(documents.rows[0]?.deletedAt).toBe(deletedAt);
    expect(audit.records).toEqual([]);
  });

  it('answers a generic 503 and keeps the document ACTIVE when the trail fails', async () => {
    const { service, documents, audit, logger } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'), 'CERTIFICATE');

    audit.fail = true;

    await expect(service.delete(OWNER, row.id)).rejects.toBeInstanceOf(ServiceUnavailableException);

    // The transaction rolled back: the row is exactly as it was.
    const stored = onlyRow(documents);

    expect(stored.status).toBe('ACTIVE');
    expect(stored.deletedAt).toBeNull();
    expect(logger.warns).toEqual([{ action: DOCUMENT_AUDIT_ACTIONS.DELETED, stage: 'persist' }]);
  });

  it('answers a generic 503 when the repository fails, with no trail written', async () => {
    const { service, documents, audit } = createHarness(new UndeletableDocuments());
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));

    await expect(service.delete(OWNER, row.id)).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(audit.records).toEqual([]);
    expect(documents.rows[0]?.status).toBe('ACTIVE');
  });

  it('refuses to delete while the profile is pending review', async () => {
    const { service, documents, audit, prisma } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));

    prisma.reviewStatus = 'PENDING';

    await expect(service.delete(OWNER, row.id)).rejects.toBeInstanceOf(ConflictException);

    // The lock is checked first: the row is untouched and no trail is written.
    expect(documents.rows[0]?.status).toBe('ACTIVE');
    expect(documents.deletions).toEqual([]);
    expect(audit.records).toEqual([]);
    expect(prisma.transactions).toEqual([]);
  });

  it('refuses to delete while the profile is approved', async () => {
    const { service, documents, audit, prisma } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));

    prisma.reviewStatus = 'APPROVED';

    await expect(service.delete(OWNER, row.id)).rejects.toBeInstanceOf(ConflictException);

    expect(documents.rows[0]?.status).toBe('ACTIVE');
    expect(audit.records).toEqual([]);
  });

  it('deletes again once the profile is only rejected', async () => {
    const { service, documents, audit, prisma } = createHarness();
    const row = documents.seed(OWNER.id, new Date('2026-01-01T00:00:00.000Z'));

    prisma.reviewStatus = 'REJECTED';

    await service.delete(OWNER, row.id);

    expect(documents.rows[0]?.status).toBe('DELETED');
    expect(audit.records).toHaveLength(1);
  });
});
