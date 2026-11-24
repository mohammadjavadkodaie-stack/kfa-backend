/**
 * Uploading and reading the photos on the athlete's own personal page.
 *
 * The order is the contract, and it is the identity-document order:
 *
 *   1. the caller's profile, resolved from the verified principal - never an id
 *      from the request;
 *   2. the quota, before a byte is scanned, encrypted or stored;
 *   3. the ingest pipeline - size, type from the magic bytes, metadata stripping,
 *      antivirus scan on the stripped bytes;
 *   4. a random object key, used as the AAD of the envelope encryption;
 *   5. the ciphertext goes to the object store, and nothing else does;
 *   6. one transaction writes the row (always PENDING) and the audit entry;
 *   7. a failure in step 6 removes the blob again, so a refused upload leaves no
 *      orphan and no trail-less row behind.
 *
 * There is no owner parameter anywhere and no public read: the list and the
 * single-photo read are keyed by the caller's own profile id, so a foreign photo
 * id answers the same generic 404 as a missing one. ADMIN/OWNER visibility is a
 * later staff step; nothing here hands a photo to anybody but its owner.
 */

import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import type { AccessPolicyContext } from '../../auth/policy/access-policy.service';
import { PrismaService } from '../../database/prisma.service';
import type { EncryptedDocument } from '../../documents/document-crypto.service';
import { DocumentCryptoService } from '../../documents/document-crypto.service';
import {
  DOCUMENT_STORAGE,
  createObjectKey,
  type DocumentStorage,
} from '../../documents/document-storage';
import type { IngestedDocument } from '../../documents/ingest/document-ingest.service';
import { DocumentIngestService } from '../../documents/ingest/document-ingest.service';
import { DocumentIngestError } from '../../documents/ingest/ingest.errors';
import type { ClaimedType, ImageType } from '../../documents/ingest/image-type';
import {
  PROFILE_PHOTO_REPOSITORY,
  type PhotoContentType,
  type ProfilePhotoRecord,
  type ProfilePhotoRepository,
  type ProfilePhotoStatus,
} from './profile-photo.repository';

/** The closed set of audit actions this module writes. */
export const PROFILE_PHOTO_AUDIT_ACTIONS = {
  UPLOADED: 'profile.photo.uploaded',
} as const;

const AUDIT_TARGET_TYPE = 'profile_photo';

/**
 * How many photos one profile may hold at once.
 *
 * Counted over PENDING and APPROVED rows only: a rejected photo stays visible to
 * its owner without consuming the allowance. The number is constant on purpose -
 * it is not configurable per request and never appears in an error.
 */
export const MAX_PROFILE_PHOTOS = 10;

/** Upper bound on one list answer, so an old profile cannot serialize forever. */
export const MAX_PROFILE_PHOTO_LIST = 100;

/** What a caller hands over: the bytes, the declared type and the sanitized caption. */
export interface ProfilePhotoUploadRequest extends ClaimedType {
  readonly bytes: Buffer;
  readonly caption: string | null;
}

/** What the API answers about one photo. No object key, no envelope, no digest. */
export interface ProfilePhotoView {
  readonly id: string;
  readonly caption: string | null;
  readonly status: ProfilePhotoStatus;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly createdAt: string;
  readonly reviewedAt: string | null;
}

export interface ProfilePhotoListView {
  readonly photos: ProfilePhotoView[];
}

/** The detector speaks in formats; the database speaks in media types. */
const CONTENT_TYPES: Readonly<Record<ImageType, PhotoContentType>> = {
  jpeg: 'image/jpeg',
  png: 'image/png',
};

function toView(record: ProfilePhotoRecord): ProfilePhotoView {
  return {
    id: record.id,
    caption: record.caption,
    status: record.status,
    contentType: record.contentType,
    sizeBytes: record.sizeBytes,
    createdAt: record.createdAt.toISOString(),
    reviewedAt: record.reviewedAt?.toISOString() ?? null,
  };
}

@Injectable()
export class ProfilePhotosService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(PROFILE_PHOTO_REPOSITORY)
    private readonly photos: ProfilePhotoRepository,
    private readonly ingest: DocumentIngestService,
    private readonly crypto: DocumentCryptoService,
    @Inject(DOCUMENT_STORAGE) private readonly storage: DocumentStorage,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * Uploads one photo for the caller. Every refusal is generic: an over-quota
   * profile and a file the pipeline refuses get the same rejection, and anything
   * failing further down gets the same unavailable answer.
   */
  async upload(
    actor: PolicySubject,
    request: ProfilePhotoUploadRequest,
    context: AccessPolicyContext,
  ): Promise<ProfilePhotoView> {
    const athleteProfileId = await this.requireProfileId(actor);

    // 1. The quota first: over the limit nothing is scanned, encrypted or stored.
    //    The refusal is the pipeline's own error on purpose, so a caller cannot
    //    tell "too many photos" from "this file was refused".
    const held = await this.photos.countAgainstQuota(athleteProfileId);

    if (held >= MAX_PROFILE_PHOTOS) throw new DocumentIngestError();

    // 2. Size, format, metadata stripping and the scan, in that order.
    const ingested = await this.ingest.process({
      bytes: request.bytes,
      claimedMime: request.claimedMime,
    });

    // 3. A key that says nothing about the owner or the file, and the AAD that
    //    binds the ciphertext to exactly this key.
    const objectKey = createObjectKey();
    const sealed = await this.seal(ingested.bytes, objectKey);

    // 4. Only ciphertext reaches the object store.
    await this.put(objectKey, sealed.ciphertext);

    // 5 and 6. The row and its trail, then the cleanup if either cannot commit.
    return this.persist(
      actor,
      athleteProfileId,
      request.caption,
      ingested,
      objectKey,
      sealed,
      context,
    );
  }

  /** The caller's own photos, newest first. No profile yet means an empty page. */
  async list(actor: PolicySubject): Promise<ProfilePhotoListView> {
    const athleteProfileId = await this.profileIdFor(actor);

    if (athleteProfileId === null) return { photos: [] };

    const records = await this.photos.listByProfile(athleteProfileId, MAX_PROFILE_PHOTO_LIST);

    return { photos: records.map(toView) };
  }

  /** One own photo. A foreign id and a missing id are the same generic 404. */
  async read(actor: PolicySubject, photoId: string): Promise<ProfilePhotoView> {
    const athleteProfileId = await this.requireProfileId(actor);
    const record = await this.photos.findByProfile(photoId, athleteProfileId);

    if (record === null) throw new NotFoundException();

    return toView(record);
  }

  /** The profile id of the caller, or null when the account has no profile yet. */
  private async profileIdFor(actor: PolicySubject): Promise<string | null> {
    const profile = await this.prisma.athleteProfile.findUnique({
      where: { userId: actor.id },
      select: { id: true },
    });

    return profile?.id ?? null;
  }

  /** Uploading or reading needs a profile; without one the answer is a generic 404. */
  private async requireProfileId(actor: PolicySubject): Promise<string> {
    const athleteProfileId = await this.profileIdFor(actor);

    if (athleteProfileId === null) throw new NotFoundException();

    return athleteProfileId;
  }

  /** Encryption failures are infrastructure failures: nothing is stored, nothing is written. */
  private async seal(plaintext: Buffer, objectKey: string): Promise<EncryptedDocument> {
    try {
      return await this.crypto.encrypt(plaintext, objectKey);
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_AUDIT_ACTIONS.UPLOADED, stage: 'encrypt' },
        'profile photo encryption failed',
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
        { action: PROFILE_PHOTO_AUDIT_ACTIONS.UPLOADED, stage: 'storage' },
        'profile photo storage write failed',
      );

      throw new ServiceUnavailableException();
    }
  }

  /**
   * One transaction for the row and its trail: the insert goes first so the chain
   * lock is held for the shortest possible time. If either fails, the blob is
   * removed again - best effort, never reported - and the answer is generic.
   */
  private async persist(
    actor: PolicySubject,
    athleteProfileId: string,
    caption: string | null,
    ingested: IngestedDocument,
    objectKey: string,
    sealed: EncryptedDocument,
    context: AccessPolicyContext,
  ): Promise<ProfilePhotoView> {
    try {
      const record = await this.prisma.$transaction(
        async (tx) => {
          const saved = await this.photos.insert(
            {
              athleteProfileId,
              objectKey,
              caption,
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

          await this.recordAttachment(actor, saved, context, tx);

          return saved;
        },
        { maxWait: 5_000, timeout: 10_000 },
      );

      return toView(record);
    } catch {
      await this.discard(objectKey);

      this.logger.warn(
        { action: PROFILE_PHOTO_AUDIT_ACTIONS.UPLOADED, stage: 'persist' },
        'profile photo upload rolled back',
      );

      throw new ServiceUnavailableException();
    }
  }

  /**
   * Fail closed: the entry is written in the same transaction, so a trail that
   * cannot be written rolls the row back and the request fails rather than report
   * a photo nobody can account for.
   *
   * The metadata is names and numbers only: the id, the status, the media type,
   * the size and whether a caption exists. Never the caption text, the digest or
   * the object key.
   */
  private async recordAttachment(
    actor: PolicySubject,
    saved: ProfilePhotoRecord,
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    await this.audit.record(
      {
        action: PROFILE_PHOTO_AUDIT_ACTIONS.UPLOADED,
        actorId: actor.id,
        actorRole: String(actor.role),
        targetType: AUDIT_TARGET_TYPE,
        targetId: saved.id,
        requestId: context.requestId,
        ip: context.ip,
        metadata: {
          photoId: saved.id,
          status: saved.status,
          contentType: saved.contentType,
          sizeBytes: saved.sizeBytes,
          hasCaption: saved.caption !== null,
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
