/**
 * Persistence boundary for the photos on an athlete's personal page.
 *
 * Every operation is keyed by the caller's profile id, which the service derives
 * from the verified principal - never from the request. The record carries the
 * encryption envelope because that is the only way to read the blob back; it
 * never carries the blob itself, a file name or a URL. The storage object key is
 * created by the service and only ever leaves this layer as that same value.
 */

import type { Prisma } from '@prisma/client';

/** DI token so the Prisma implementation can be swapped in tests. */
export const PROFILE_PHOTO_REPOSITORY = Symbol('PROFILE_PHOTO_REPOSITORY');

/** The states a photo moves through: uploaded, then a reviewer decides. */
export type ProfilePhotoStatus = 'PENDING' | 'APPROVED' | 'REJECTED';

/** The two formats the ingest pipeline produces and the only ones the table accepts. */
export type PhotoContentType = 'image/jpeg' | 'image/png';

/**
 * Everything an upload writes. `status` is deliberately absent: the column
 * defaults to PENDING, so no caller can create an approved photo. The id, the
 * timestamps and the review columns come from the database too.
 */
export interface ProfilePhotoInsert {
  readonly athleteProfileId: string;
  readonly objectKey: string;
  readonly caption: string | null;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly keyId: string;
  readonly wrappedDek: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;
}

/** One stored photo, as the database holds it. */
export interface ProfilePhotoRecord extends ProfilePhotoInsert {
  readonly id: string;
  readonly status: ProfilePhotoStatus;
  readonly createdAt: Date;
  readonly reviewedAt: Date | null;
  readonly reviewedById: string | null;
}

export interface ProfilePhotoRepository {
  /**
   * Inserts one row, always as PENDING, and returns it as stored.
   *
   * A caller that already owns a transaction passes it as `tx`, so the row joins
   * the same unit of work as the audit entry that describes it.
   */
  insert(record: ProfilePhotoInsert, tx?: Prisma.TransactionClient): Promise<ProfilePhotoRecord>;

  /**
   * How many photos count against the quota: PENDING and APPROVED.
   *
   * REJECTED rows are the owner's to see and not the owner's to be punished for,
   * so they never consume the allowance.
   */
  countAgainstQuota(athleteProfileId: string, tx?: Prisma.TransactionClient): Promise<number>;

  /** The owner's photos, newest first, at most `limit`; never another profile's. */
  listByProfile(
    athleteProfileId: string,
    limit: number,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord[]>;

  /**
   * One photo by id and profile id, or null.
   *
   * Both ids are in the predicate, so a photo of another profile answers exactly
   * like a photo that does not exist and the caller cannot tell the two apart.
   */
  findByProfile(
    photoId: string,
    athleteProfileId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord | null>;
}
