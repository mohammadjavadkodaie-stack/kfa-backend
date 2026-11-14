/**
 * Persistence boundary for identity documents.
 *
 * A row is written once, by the upload service, and every operation is keyed by
 * the owner. The record carries the encryption envelope because that is the only
 * way to read the blob back; it never carries the blob itself, a file name or a
 * URL, and the storage object key never leaves this layer except as a value the
 * caller already created.
 */

import type { Prisma } from '@prisma/client';

/** DI token so the Prisma implementation can be swapped in tests. */
export const IDENTITY_DOCUMENT_REPOSITORY = Symbol('IDENTITY_DOCUMENT_REPOSITORY');

/** What the document is, not what it contains. */
export type DocumentKind = 'NATIONAL_ID' | 'MEDAL' | 'CERTIFICATE';

/** The two formats the ingest pipeline produces and the only ones the table accepts. */
export type DocumentContentType = 'image/jpeg' | 'image/png';

/** A document leaves the active set only through the retention step, which is later. */
export type DocumentStatus = 'ACTIVE' | 'DELETED';

/**
 * Everything an upload writes. The id, the status and the timestamps come from
 * the database, so a caller cannot choose them.
 */
export interface IdentityDocumentInsert {
  readonly ownerUserId: string;
  readonly kind: DocumentKind;
  readonly objectKey: string;
  readonly contentType: DocumentContentType;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly keyId: string;
  readonly wrappedDek: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;
}

/** One stored document, as the database holds it. */
export interface IdentityDocumentRecord extends IdentityDocumentInsert {
  readonly id: string;
  readonly status: DocumentStatus;
  readonly createdAt: Date;
  readonly deletedAt: Date | null;
}

export interface IdentityDocumentRepository {
  /**
   * Inserts one row and returns it as stored.
   *
   * A caller that already owns a transaction passes it as `tx`, so the row joins
   * the same unit of work as the audit row that describes it.
   */
  insert(
    record: IdentityDocumentInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord>;

  /** The per-owner quota: how many ACTIVE documents the account already holds. */
  countActiveByOwner(ownerUserId: string, tx?: Prisma.TransactionClient): Promise<number>;

  /**
   * One ACTIVE row by id, or null.
   *
   * The view path needs this rather than a lookup by owner: a staff reader is not
   * the owner, so the row has to be read first and the decision made afterwards
   * by the authorization policy - never by the query. A soft-deleted row is not
   * viewable, so it answers null exactly like a missing one.
   */
  findActiveById(id: string, tx?: Prisma.TransactionClient): Promise<IdentityDocumentRecord | null>;

  /**
   * The owner's own ACTIVE documents, newest first, at most `limit`.
   *
   * The order is total (creation time, then id), so two requests with the same
   * rows cannot disagree about it. Only ACTIVE rows are read: the list is the
   * same set the quota counts.
   */
  listActiveByOwner(
    ownerUserId: string,
    limit: number,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord[]>;

  /**
   * Soft-deletes one ACTIVE document of one owner and returns it, or null.
   *
   * A compare-and-set on (id, owner, ACTIVE): a row that is missing, belongs to
   * somebody else or was already deleted answers null in exactly the same way,
   * and two racing deletes cannot both count as successful - the loser sees the
   * predicate fail and gets the same null. The caller passes its transaction so
   * the audit entry describing the delete commits or rolls back with it.
   */
  softDeleteOwnedActive(
    documentId: string,
    ownerUserId: string,
    deletedAt: Date,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null>;
}
