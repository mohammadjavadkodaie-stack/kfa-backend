/**
 * The owner's own documents: listing them and revoking one.
 *
 * Both operations are keyed by the caller, never by a value from the request:
 * the owner is the verified principal, so there is no parameter that could
 * point at another account. The list answer is the five identity fields a page
 * needs - id, kind, media type, size and creation time - and nothing that would
 * locate, fingerprint or decrypt the blob.
 *
 * A delete is a soft delete: the row moves to DELETED in the same transaction
 * as the audit entry that describes it, so an entry that cannot be written
 * rolls the row back and the request fails closed. The encrypted blob itself is
 * left in the object store on purpose - a retention job removes it later - and
 * this service never touches it.
 *
 * Refusals are deliberately uniform: a missing document, a document of another
 * account and an already deleted one answer one generic 404, and a database or
 * audit failure answers one generic 503.
 */

import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { PrismaService } from '../../database/prisma.service';
import { DOCUMENT_AUDIT_ACTIONS } from './document-upload.service';
import {
  IDENTITY_DOCUMENT_REPOSITORY,
  type DocumentContentType,
  type DocumentKind,
  type IdentityDocumentRecord,
  type IdentityDocumentRepository,
} from './identity-document.repository';

/**
 * How many documents one list answer may carry.
 *
 * The quota is ten, so this is not a second limit a caller can hit in normal
 * use; it is a bound on the work one request can cause, so a corrupt or
 * imported account cannot make the route read an unbounded set.
 */
export const MAX_LISTED_DOCUMENTS = 100;

const AUDIT_TARGET_TYPE = 'identity_document';

/** The log action of a failed list; no audit row is written for a read. */
const LIST_ACTION = 'document.list';

/** What one document looks like in the list. No key, envelope or owner id. */
export interface OwnedDocumentSummary {
  readonly id: string;
  readonly kind: DocumentKind;
  readonly contentType: DocumentContentType;
  readonly sizeBytes: number;
  readonly createdAt: Date;
}

/** The whole list answer; the quota is never part of it. */
export interface OwnedDocumentList {
  readonly documents: readonly OwnedDocumentSummary[];
}

function toSummary(record: IdentityDocumentRecord): OwnedDocumentSummary {
  return {
    id: record.id,
    kind: record.kind,
    contentType: record.contentType,
    sizeBytes: record.sizeBytes,
    createdAt: record.createdAt,
  };
}

@Injectable()
export class OwnerDocumentsService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(IDENTITY_DOCUMENT_REPOSITORY)
    private readonly documents: IdentityDocumentRepository,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /** The caller's own ACTIVE documents, newest first, at most the cap. */
  async list(actor: PolicySubject): Promise<OwnedDocumentList> {
    let rows: IdentityDocumentRecord[];

    try {
      rows = await this.documents.listActiveByOwner(actor.id, MAX_LISTED_DOCUMENTS);
    } catch {
      this.logger.warn({ action: LIST_ACTION, stage: 'repository' }, 'document list failed');

      throw new ServiceUnavailableException();
    }

    // A fresh object per item, built field by field: the record's envelope and
    // owner are not copied, so no future column can leak through this route.
    return { documents: rows.map(toSummary) };
  }

  /**
   * Soft-deletes one ACTIVE document of the caller, or answers the generic 404.
   *
   * The row and the trail share one transaction: the compare-and-set runs first
   * and the entry joins the same client, so the delete is either fully recorded
   * or not applied at all. The blob is intentionally not removed here.
   */
  async delete(actor: PolicySubject, documentId: string): Promise<void> {
    let deleted: IdentityDocumentRecord | null;

    try {
      deleted = await this.prisma.$transaction(
        async (tx) => {
          const row = await this.documents.softDeleteOwnedActive(
            documentId,
            actor.id,
            new Date(),
            tx,
          );

          if (row === null) return null;

          await this.record(actor, row, tx);

          return row;
        },
        { maxWait: 5_000, timeout: 10_000 },
      );
    } catch {
      this.logger.warn(
        { action: DOCUMENT_AUDIT_ACTIONS.DELETED, stage: 'persist' },
        'document delete rolled back',
      );

      throw new ServiceUnavailableException();
    }

    // Missing, foreign and already deleted all arrive here as the same null.
    if (deleted === null) throw new NotFoundException();
  }

  /**
   * Fail closed, like the upload: the entry is written in the same transaction,
   * so a trail that cannot be written leaves the document ACTIVE and the request
   * fails rather than report a delete nobody can account for.
   *
   * The metadata is the id and the kind, nothing else: no object key, no digest,
   * no envelope, no file name.
   */
  private async record(
    actor: PolicySubject,
    deleted: IdentityDocumentRecord,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    await this.audit.record(
      {
        action: DOCUMENT_AUDIT_ACTIONS.DELETED,
        actorId: actor.id,
        actorRole: String(actor.role),
        targetType: AUDIT_TARGET_TYPE,
        targetId: deleted.id,
        metadata: { documentId: deleted.id, kind: deleted.kind },
      },
      tx,
    );
  }
}
