/**
 * Uploading one identity document.
 *
 * The service owns the order of the steps, and the order is the contract:
 *
 *   1. the per-owner quota, before a byte is scanned, encrypted or stored;
 *   2. the ingest pipeline - size, type from the magic bytes, metadata stripping,
 *      antivirus scan on the stripped bytes;
 *   3. a random object key, used as the AAD of the envelope encryption;
 *   4. the ciphertext goes to the object store, and nothing else does;
 *   5. one transaction writes the row first and the audit entry last;
 *   6. a failure in step 5 removes the blob again, so a refused upload leaves no
 *      orphan and no trail-less row behind.
 *
 * There is no endpoint here and no owner parameter anywhere: the row is always
 * written for the authenticated caller, so a request cannot point at another
 * account. A stored document is never returned: the caller gets its id, its kind,
 * its type and its size, and learns nothing about the key or the digest.
 */

import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { PrismaService } from '../../database/prisma.service';
import type { EncryptedDocument } from '../document-crypto.service';
import { DocumentCryptoService } from '../document-crypto.service';
import { DOCUMENT_STORAGE, createObjectKey, type DocumentStorage } from '../document-storage';
import type { IngestedDocument } from '../ingest/document-ingest.service';
import { DocumentIngestService } from '../ingest/document-ingest.service';
import { DocumentIngestError } from '../ingest/ingest.errors';
import type { ClaimedType, ImageType } from '../ingest/image-type';
import {
  IDENTITY_DOCUMENT_REPOSITORY,
  type DocumentContentType,
  type DocumentKind,
  type IdentityDocumentRecord,
  type IdentityDocumentRepository,
} from './identity-document.repository';

/** The closed set of audit actions this module writes. */
export const DOCUMENT_AUDIT_ACTIONS = {
  UPLOADED: 'document.uploaded',
} as const;

export type DocumentAuditAction =
  (typeof DOCUMENT_AUDIT_ACTIONS)[keyof typeof DOCUMENT_AUDIT_ACTIONS];

const AUDIT_TARGET_TYPE = 'identity_document';

/**
 * How many documents one account may hold at once.
 *
 * Counted over ACTIVE rows only, so the quota is exactly what a user sees in
 * their own list. The number is constant on purpose: it is not configurable per
 * request and never appears in an error.
 */
export const MAX_ACTIVE_DOCUMENTS = 10;

/** What a caller hands over: the bytes, the kind, and the two untrusted claims. */
export interface DocumentUploadRequest extends ClaimedType {
  readonly kind: DocumentKind;
  readonly bytes: Buffer;
}

/** What the upload returns. No object key, no envelope, no digest. */
export interface DocumentUploadView {
  readonly id: string;
  readonly kind: DocumentKind;
  readonly contentType: DocumentContentType;
  readonly sizeBytes: number;
}

/** The detector speaks in formats; the database speaks in media types. */
const CONTENT_TYPES: Readonly<Record<ImageType, DocumentContentType>> = {
  jpeg: 'image/jpeg',
  png: 'image/png',
};

function toView(record: IdentityDocumentRecord): DocumentUploadView {
  return {
    id: record.id,
    kind: record.kind,
    contentType: record.contentType,
    sizeBytes: record.sizeBytes,
  };
}

@Injectable()
export class DocumentUploadService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(IDENTITY_DOCUMENT_REPOSITORY)
    private readonly documents: IdentityDocumentRepository,
    private readonly ingest: DocumentIngestService,
    private readonly crypto: DocumentCryptoService,
    @Inject(DOCUMENT_STORAGE) private readonly storage: DocumentStorage,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * Uploads one document for the caller. Every refusal is generic: the same
   * rejection for an over-quota account and for a file the pipeline refuses, and
   * the same unavailable answer for anything that failed further down.
   */
  async upload(actor: PolicySubject, request: DocumentUploadRequest): Promise<DocumentUploadView> {
    // 1. The quota first. Over the limit the upload stops here, before the scan,
    //    the encryption and the store, so an over-quota account costs nothing.
    //    The refusal is the pipeline's own rejection on purpose: a caller cannot
    //    tell "too many documents" from "this file was refused", so the limit
    //    cannot be probed one upload at a time.
    const active = await this.documents.countActiveByOwner(actor.id);

    if (active >= MAX_ACTIVE_DOCUMENTS) throw new DocumentIngestError();

    // 2. Size, format, metadata stripping and the scan. Everything below works on
    //    the buffer this returns, never on the upload.
    const ingested = await this.ingest.process({
      bytes: request.bytes,
      claimedExtension: request.claimedExtension,
      claimedMime: request.claimedMime,
    });

    // 3. A key that says nothing about the owner or the file, and the AAD that
    //    binds the ciphertext to exactly this key.
    const objectKey = createObjectKey();
    const sealed = await this.seal(ingested.bytes, objectKey);

    // 4. Only ciphertext reaches the object store.
    await this.put(objectKey, sealed.ciphertext);

    // 5 and 6. The row and its trail, then the cleanup if either cannot commit.
    return this.persist(actor, request.kind, ingested, objectKey, sealed);
  }

  /** Encryption failures are infrastructure failures: nothing is stored, nothing is written. */
  private async seal(plaintext: Buffer, objectKey: string): Promise<EncryptedDocument> {
    try {
      return await this.crypto.encrypt(plaintext, objectKey);
    } catch {
      this.logger.warn(
        { action: DOCUMENT_AUDIT_ACTIONS.UPLOADED, stage: 'encrypt' },
        'document encryption failed',
      );

      throw new ServiceUnavailableException();
    }
  }

  /** A failed write leaves the row untouched: the database is only reached afterwards. */
  private async put(objectKey: string, ciphertext: Buffer): Promise<void> {
    try {
      await this.storage.put(objectKey, ciphertext);
    } catch {
      this.logger.warn(
        { action: DOCUMENT_AUDIT_ACTIONS.UPLOADED, stage: 'storage' },
        'document storage write failed',
      );

      throw new ServiceUnavailableException();
    }
  }

  /**
   * One transaction for the row and its trail: the insert goes first so the chain
   * lock is held for the shortest possible time, and the audit entry joins the
   * same client. If either fails, the blob is removed again - best effort, and
   * never reported to the caller - and the answer is the same generic failure.
   */
  private async persist(
    actor: PolicySubject,
    kind: DocumentKind,
    ingested: IngestedDocument,
    objectKey: string,
    sealed: EncryptedDocument,
  ): Promise<DocumentUploadView> {
    try {
      const record = await this.prisma.$transaction(
        async (tx) => {
          const saved = await this.insertFor(actor, kind, ingested, objectKey, sealed, tx);

          await this.record(actor, saved, tx);

          return saved;
        },
        { maxWait: 5_000, timeout: 10_000 },
      );

      return toView(record);
    } catch {
      await this.discard(objectKey);

      this.logger.warn(
        { action: DOCUMENT_AUDIT_ACTIONS.UPLOADED, stage: 'persist' },
        'document upload rolled back',
      );

      throw new ServiceUnavailableException();
    }
  }

  private insertFor(
    actor: PolicySubject,
    kind: DocumentKind,
    ingested: IngestedDocument,
    objectKey: string,
    sealed: EncryptedDocument,
    tx: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord> {
    return this.documents.insert(
      {
        // The verified principal, never an id from the request.
        ownerUserId: actor.id,
        kind,
        objectKey,
        contentType: CONTENT_TYPES[ingested.type],
        // What is stored is the sanitized buffer, so that is what the row describes.
        sizeBytes: ingested.bytes.length,
        sha256: ingested.sha256,
        keyId: sealed.keyId,
        wrappedDek: sealed.wrappedDek,
        iv: sealed.iv,
        authTag: sealed.authTag,
      },
      tx,
    );
  }

  /**
   * Fail closed, like the admin and athlete writes: the entry is written in the
   * same transaction, so a trail that cannot be written rolls the row back and
   * the request fails rather than report an upload nobody can account for.
   *
   * The metadata is names and numbers only: the id, the kind, the media type and
   * the size. No digest, no object key, no file name, no bytes.
   */
  private async record(
    actor: PolicySubject,
    saved: IdentityDocumentRecord,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    await this.audit.record(
      {
        action: DOCUMENT_AUDIT_ACTIONS.UPLOADED,
        actorId: actor.id,
        actorRole: String(actor.role),
        targetType: AUDIT_TARGET_TYPE,
        targetId: saved.id,
        metadata: {
          documentId: saved.id,
          kind: saved.kind,
          contentType: saved.contentType,
          sizeBytes: saved.sizeBytes,
        },
      },
      tx,
    );
  }

  /** Best effort: the upload has already failed and the key never reaches the client. */
  private async discard(objectKey: string): Promise<void> {
    try {
      await this.storage.delete(objectKey);
    } catch {
      // Nothing else to do, and nothing to tell the caller.
    }
  }
}
