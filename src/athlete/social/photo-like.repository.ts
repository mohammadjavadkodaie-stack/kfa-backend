/**
 * The storage seam behind a photo like.
 *
 * One row per (photo, user), enforced by a unique pair: a repeated PUT and a
 * repeated DELETE are both silent no-ops. The interface exposes a count and
 * nothing else about who liked - no user id ever leaves this layer.
 */

import type { ProfilePhotoStatus } from '../photos/profile-photo.repository';

/** DI token so the Prisma implementation can be swapped in tests. */
export const PHOTO_LIKE_REPOSITORY = Symbol('PHOTO_LIKE_REPOSITORY');

/** The only facts a like needs from the photo: its status and its owner. */
export interface LikeablePhoto {
  readonly id: string;
  readonly status: ProfilePhotoStatus;
  /** The account the photo belongs to; the one person who may not like it. */
  readonly userId: string;
}

export interface PhotoLikeRepository {
  /** One photo by id, whatever its status; `null` when there is no such row. */
  findPhoto(photoId: string): Promise<LikeablePhoto | null>;

  /** `false` when the same user already liked this photo. */
  create(photoId: string, userId: string): Promise<boolean>;

  /** Removes the pair; 0 when the user had not liked the photo. */
  remove(photoId: string, userId: string): Promise<number>;

  /** How many accounts liked one photo. Never who they are. */
  count(photoId: string): Promise<number>;
}
