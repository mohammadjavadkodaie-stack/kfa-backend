/**
 * The storage seam behind a photo report.
 *
 * A report is written once per (photo, reporter): the unique pair is enforced by
 * the database, and this interface turns that violation into a plain `false`
 * instead of an error, so a duplicate report is indistinguishable from a fresh
 * one on the wire. The reporter's identity is read by staff only through the
 * aggregated count, never from here.
 */

import type { ProfilePhotoStatus } from './profile-photo.repository';

export const PROFILE_PHOTO_REPORT_REPOSITORY = Symbol('PROFILE_PHOTO_REPORT_REPOSITORY');

/** The fixed reason codes, mirroring the `PhotoReportReason` enum. */
export type PhotoReportReason = 'SPAM' | 'ABUSE' | 'NUDITY' | 'OTHER';

/** The only facts a report needs from the photo; nothing else is read. */
export interface ReportablePhoto {
  readonly id: string;
  readonly status: ProfilePhotoStatus;
  /** The account that owns the photo; the one person who may not report it. */
  readonly ownerUserId: string;
}

export interface PhotoReportInput {
  readonly photoId: string;
  readonly reporterUserId: string;
  readonly reason: PhotoReportReason;
  /** Already trimmed and control-free; `null` when the caller wrote nothing. */
  readonly note: string | null;
}

export interface ProfilePhotoReportRepository {
  /** One photo by id, whatever its status; `null` when there is no such row. */
  findReportablePhoto(photoId: string): Promise<ReportablePhoto | null>;

  /**
   * Appends one report. Returns `false` when the same user already reported this
   * photo - the unique pair, not a read-then-write, is what decides.
   */
  create(report: PhotoReportInput): Promise<boolean>;
}
