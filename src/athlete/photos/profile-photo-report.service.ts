/**
 * Reporting someone else's profile photo.
 *
 * The order is the whole policy:
 *
 *   1. the caller is authenticated, by the global guard;
 *   2. only a photo the public may see can be reported - a missing id and a
 *      PENDING, REJECTED or REMOVED photo are the same generic 404, so a report
 *      is not a way to learn what waits behind the review queue;
 *   3. a photo may not be reported by the account that owns it, generic 403;
 *   4. a second report by the same user is a silent no-op, so the caller cannot
 *      tell a fresh report from a duplicate and cannot inflate a count.
 *
 * There is no audit row here: the report itself is the record. It is append-only
 * and the staff list only ever reads counts from it.
 */

import { ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PolicySubject } from '../../auth/policy/access-policy';
import {
  PROFILE_PHOTO_REPORT_REPOSITORY,
  type ProfilePhotoReportRepository,
} from './profile-photo-report.repository';
import type { PhotoReportRequest } from './profile-photo-report.dto';

@Injectable()
export class ProfilePhotoReportService {
  constructor(
    @Inject(PROFILE_PHOTO_REPORT_REPOSITORY)
    private readonly reports: ProfilePhotoReportRepository,
  ) {}

  async report(actor: PolicySubject, photoId: string, request: PhotoReportRequest): Promise<void> {
    const target = await this.reports.findReportablePhoto(photoId);

    // Only a photo that is public right now may be reported.
    if (target === null || target.status !== 'APPROVED') throw new NotFoundException();

    // Your own photo is not a report; the refusal carries no detail.
    if (target.ownerUserId === actor.id) throw new ForbiddenException();

    // `false` means the same user reported this photo before. Nothing is written
    // and nothing is said: the answer is the same 204 as the first time.
    await this.reports.create({
      photoId: target.id,
      reporterUserId: actor.id,
      reason: request.reason,
      note: request.note,
    });
  }
}
