import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import type {
  DocumentKind,
  IdentityDocumentInsert,
  IdentityDocumentRecord,
  IdentityDocumentRepository,
} from '../identity-document.repository';

/**
 * The `identity_document` table without PostgreSQL, for the upload specs.
 *
 * It keeps the two guarantees the service leans on - a row is written once and
 * only ACTIVE rows count towards the quota - and nothing else: the CHECK
 * constraints belong to the database and are proved by the database suite.
 */
export class InMemoryIdentityDocuments implements IdentityDocumentRepository {
  private readonly rowsById = new Map<string, IdentityDocumentRecord>();
  /** Every insert attempt, in order, so a refused upload can be shown to write nothing. */
  readonly inserts: IdentityDocumentRecord[] = [];
  /** The owner of every quota read, in order. */
  readonly counts: string[] = [];
  /** Every id the view path asked for, in order. */
  readonly reads: string[] = [];
  /** Every owner list read, with the cap it asked for, in order. */
  readonly lists: { ownerUserId: string; limit: number }[] = [];
  /** Every delete attempt, in order - foreign and missing ones included. */
  readonly deletions: { documentId: string; ownerUserId: string }[] = [];
  /** The client each insert went through; `undefined` when the call had none. */
  readonly transactions: (Prisma.TransactionClient | undefined)[] = [];

  get rows(): IdentityDocumentRecord[] {
    return [...this.rowsById.values()];
  }

  async insert(
    record: IdentityDocumentInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord> {
    this.transactions.push(tx);

    const row: IdentityDocumentRecord = {
      ...record,
      id: randomUUID(),
      status: 'ACTIVE',
      createdAt: new Date(),
      deletedAt: null,
    };

    this.rowsById.set(row.id, row);
    this.inserts.push(row);

    return row;
  }

  async countActiveByOwner(ownerUserId: string, _tx?: Prisma.TransactionClient): Promise<number> {
    this.counts.push(ownerUserId);

    return this.rows.filter((row) => row.ownerUserId === ownerUserId && row.status === 'ACTIVE')
      .length;
  }

  async findActiveById(
    id: string,
    _tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null> {
    this.reads.push(id);

    const row = this.rowsById.get(id);

    // Same rule as the query: a soft-deleted row is not found.
    return row === undefined || row.status !== 'ACTIVE' ? null : row;
  }

  async listActiveByOwner(
    ownerUserId: string,
    limit: number,
    _tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord[]> {
    this.lists.push({ ownerUserId, limit });

    // Same predicate and total order as the query: ACTIVE only, newest first,
    // the id breaking a tie, at most `limit` rows.
    return this.rows
      .filter((row) => row.ownerUserId === ownerUserId && row.status === 'ACTIVE')
      .sort(
        (left, right) =>
          right.createdAt.getTime() - left.createdAt.getTime() || right.id.localeCompare(left.id),
      )
      .slice(0, limit);
  }

  async softDeleteOwnedActive(
    documentId: string,
    ownerUserId: string,
    deletedAt: Date,
    _tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null> {
    this.deletions.push({ documentId, ownerUserId });

    const row = this.rowsById.get(documentId);

    // The compare-and-set of the query: a missing, foreign or already deleted
    // row is not moved, and the caller cannot tell the three apart.
    if (row === undefined || row.ownerUserId !== ownerUserId || row.status !== 'ACTIVE') {
      return null;
    }

    const deleted: IdentityDocumentRecord = { ...row, status: 'DELETED', deletedAt };

    this.rowsById.set(documentId, deleted);

    return deleted;
  }

  /** The committed state a rollback has to bring back. */
  snapshot(): Map<string, IdentityDocumentRecord> {
    return new Map(this.rowsById);
  }

  restore(snapshot: Map<string, IdentityDocumentRecord>): void {
    this.rowsById.clear();
    snapshot.forEach((row, id) => this.rowsById.set(id, row));
  }

  /** Marks one row DELETED, as the retention step will. */
  softDelete(id: string): void {
    const row = this.rowsById.get(id);

    if (row === undefined) return;

    this.rowsById.set(id, { ...row, status: 'DELETED', deletedAt: new Date() });
  }

  /** Puts `count` ACTIVE rows on the owner, for the quota checks. */
  seedActive(ownerUserId: string, count: number, kind: DocumentKind = 'NATIONAL_ID'): void {
    for (let index = 0; index < count; index += 1) {
      this.seed(ownerUserId, new Date(), kind);
    }
  }

  /**
   * Puts one ACTIVE row on the owner at a chosen time, for the ordering checks.
   * Returns the row, so a test can address exactly what it seeded.
   */
  seed(
    ownerUserId: string,
    createdAt: Date,
    kind: DocumentKind = 'NATIONAL_ID',
  ): IdentityDocumentRecord {
    const id = randomUUID();
    const row: IdentityDocumentRecord = {
      id,
      ownerUserId,
      kind,
      objectKey: randomUUID(),
      contentType: 'image/jpeg',
      sizeBytes: 1_024,
      sha256: '9f'.repeat(32),
      keyId: 'v1',
      wrappedDek: Buffer.alloc(61, 1),
      iv: Buffer.alloc(12, 2),
      authTag: Buffer.alloc(16, 3),
      status: 'ACTIVE',
      createdAt,
      deletedAt: null,
    };

    this.rowsById.set(id, row);

    return row;
  }
}
