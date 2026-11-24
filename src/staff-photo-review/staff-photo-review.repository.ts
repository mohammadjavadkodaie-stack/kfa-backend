/**
 * Persistence boundary for the staff moderation queue of profile photos.
 *
 * Metadata only: no method here returns the object key, the encryption envelope,
 * the digest or a view link. The queue and the decision work from the row's
 * descriptive columns; the bytes stay behind the owner's own routes.
 */

import type { Prisma } from '@prisma/client';
import type {
  PhotoContentType,
  ProfilePhotoStatus,
} from '../athlete/photos/profile-photo.repository';

/** DI token so the Prisma implementation can be swapped in tests. */
export const STAFF_PHOTO_REVIEW_REPOSITORY = Symbol('STAFF_PHOTO_REVIEW_REPOSITORY');

/** The columns one queue row may carry. */
export interface PendingPhotoRow {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly caption: string | null;
  readonly createdAt: Date;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
}

/**
 * What a decision needs. `ownerUserId` is the account behind the profile, so the
 * service can refuse a self-review; it is never returned to a client.
 */
export interface PhotoReviewTarget {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly ownerUserId: string;
  readonly status: ProfilePhotoStatus;
}

/** The two outcomes a reviewer can record. There is no third. */
export interface PhotoReviewDecision {
  readonly status: 'APPROVED' | 'REJECTED';
  readonly reviewedAt: Date;
  readonly reviewedById: string;
}

export interface StaffPhotoReviewRepository {
  /**
   * PENDING photos, oldest first, at most `limit + 1` rows: the extra row is how
   * the service knows there is a next page without a second query.
   */
  listPending(limit: number, cursor?: string): Promise<PendingPhotoRow[]>;

  /** One photo by id, whatever its status; `null` when there is no such row. */
  findForReview(photoId: string): Promise<PhotoReviewTarget | null>;

  /**
   * One conditional UPDATE: the predicate is `status = PENDING`, so a photo
   * leaves the queue exactly once. Returns the number of rows changed, which is
   * zero when another reviewer got there first.
   */
  applyDecision(
    photoId: string,
    decision: PhotoReviewDecision,
    tx?: Prisma.TransactionClient,
  ): Promise<number>;
}
