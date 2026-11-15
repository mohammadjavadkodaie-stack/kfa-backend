import { randomUUID } from 'node:crypto';
import type {
  DocumentKind,
  DocumentStatus,
} from '../../src/documents/records/identity-document.repository';
import type {
  ReviewDocumentMetadata,
  ReviewRecipient,
  StaffReviewRepository,
} from '../../src/staff-review/staff-review.repository';

/** One stored row: the metadata the queue returns plus the status that filters it. */
export interface StoredReviewDocument extends ReviewDocumentMetadata {
  readonly status: DocumentStatus;
}

export interface SeedDocumentInput {
  readonly kind?: DocumentKind;
  readonly sizeBytes?: number;
  readonly createdAt?: Date;
  /** Defaults to ACTIVE; `DELETED` rows must never be counted or listed. */
  readonly status?: DocumentStatus;
}

/**
 * The document and account columns the review routes read, without PostgreSQL.
 *
 * The two predicates the Prisma implementation pushes into SQL - ACTIVE only,
 * newest first - are repeated here, so a suite can prove that a deleted row
 * disappears from both the count and the detail page.
 */
export class InMemoryStaffReviews implements StaffReviewRepository {
  readonly documents = new Map<string, StoredReviewDocument[]>();
  /** Where a decision email would go; absent means "no address on file". */
  readonly recipients = new Map<string, ReviewRecipient>();
  /** Every `countActiveDocuments` call, so a suite can see the page it asked about. */
  readonly counted: string[][] = [];

  /** Set to throw from one read, to prove that a failed read never fails a decision. */
  failRecipientWith: Error | null = null;

  /** Adds one document and returns the stored row. */
  addDocument(ownerUserId: string, input: SeedDocumentInput = {}): StoredReviewDocument {
    const document: StoredReviewDocument = {
      id: randomUUID(),
      kind: input.kind ?? 'NATIONAL_ID',
      sizeBytes: input.sizeBytes ?? 1_024,
      createdAt: input.createdAt ?? new Date(),
      status: input.status ?? 'ACTIVE',
    };
    const rows = this.documents.get(ownerUserId) ?? [];

    rows.push(document);
    this.documents.set(ownerUserId, rows);

    return document;
  }

  async countActiveDocuments(
    ownerUserIds: readonly string[],
  ): Promise<ReadonlyMap<string, number>> {
    this.counted.push([...ownerUserIds]);

    const counts = new Map<string, number>();

    for (const ownerUserId of ownerUserIds) {
      const active = (this.documents.get(ownerUserId) ?? []).filter(
        (document) => document.status === 'ACTIVE',
      );

      if (active.length > 0) counts.set(ownerUserId, active.length);
    }

    return counts;
  }

  async listActiveDocuments(ownerUserId: string): Promise<ReviewDocumentMetadata[]> {
    return (this.documents.get(ownerUserId) ?? [])
      .filter((document) => document.status === 'ACTIVE')
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || a.id.localeCompare(b.id))
      .map(({ status: _status, ...metadata }) => metadata);
  }

  async findRecipient(profileId: string): Promise<ReviewRecipient | null> {
    if (this.failRecipientWith !== null) throw this.failRecipientWith;

    return this.recipients.get(profileId) ?? null;
  }
}
