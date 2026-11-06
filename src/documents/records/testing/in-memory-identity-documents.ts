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

  /** The committed state a rollback has to bring back. */
  snapshot(): Map<string, IdentityDocumentRecord> {
    return new Map(this.rowsById);
  }

  restore(snapshot: Map<string, IdentityDocumentRecord>): void {
    this.rowsById.clear();
    snapshot.forEach((row, id) => this.rowsById.set(id, row));
  }

  /** Puts `count` ACTIVE rows on the owner, for the quota checks. */
  seedActive(ownerUserId: string, count: number, kind: DocumentKind = 'NATIONAL_ID'): void {
    for (let index = 0; index < count; index += 1) {
      const id = randomUUID();

      this.rowsById.set(id, {
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
        createdAt: new Date(),
        deletedAt: null,
      });
    }
  }
}
