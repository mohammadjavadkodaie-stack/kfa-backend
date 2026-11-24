import type { PhotoContentType, ProfilePhotoRecord } from './profile-photo.repository';

/**
 * Persistence boundary for the profile-photo *view* stack: what it needs to
 * serve bytes and to list publicly visible photos. It is separate from the
 * upload repository on purpose — the view stack never writes, and its list
 * query cannot accidentally grow an object-key column.
 */
export const PROFILE_PHOTO_VIEW_REPOSITORY = Symbol('PROFILE_PHOTO_VIEW_REPOSITORY');

/** A photo row plus the account that owns it (the owner of the profile). */
export interface ProfilePhotoViewRecord {
  readonly photo: ProfilePhotoRecord;
  readonly ownerUserId: string;
}

/**
 * The columns a public listing may carry: metadata only — never the object
 * key, the envelope or the digest.
 */
export interface ApprovedPhotoSummary {
  readonly id: string;
  readonly caption: string | null;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly createdAt: Date;
}

export interface ProfilePhotoViewRepository {
  /**
   * One row by id, whatever its status. The *caller* decides which statuses
   * may be served, because that decision is time-sensitive (a photo approved
   * after a link was issued must be denied again the moment it is rejected).
   */
  findById(photoId: string): Promise<ProfilePhotoViewRecord | null>;

  /**
   * The APPROVED rows of one profile, newest first, at most `limit` of them;
   * `cursor` resumes after the row with that id (the repository's own `id`
   * column, so a cursor from an earlier page never means "the next profile").
   */
  listApproved(
    athleteProfileId: string,
    limit: number,
    cursor?: string,
  ): Promise<ApprovedPhotoSummary[]>;
}
