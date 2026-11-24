/**
 * The staff moderation queue for profile photos.
 *
 * Metadata only: a queue row carries the photo's id, its profile id, the caption
 * the athlete wrote, when it arrived, the media type and the size. No object key,
 * no digest, no view link and no bytes - a reviewer never reads the image
 * through this feature.
 *
 * The order is the staff review order:
 *
 *   1. the caller is a staff principal, guaranteed by the guards in front;
 *   2. a reviewer may not decide on their own profile - the queue is a second
 *      pair of eyes;
 *   3. only a PENDING photo can transition, otherwise the generic 409;
 *   4. the conditional UPDATE and the audit row share one transaction, so a
 *      decision nobody can account for does not happen at all.
 */

import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { CLOCK, type Clock } from '../athlete/profile/athlete-age';
import type { PhotoContentType } from '../athlete/photos/profile-photo.repository';
import { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { PrismaService } from '../database/prisma.service';
import {
  DEFAULT_PHOTO_REVIEW_PAGE_SIZE,
  MAX_PHOTO_REJECTION_REASON_LENGTH,
  MAX_PHOTO_TAKEDOWN_REASON_LENGTH,
} from './staff-photo-review.dto';
import {
  STAFF_PHOTO_REVIEW_REPOSITORY,
  type PhotoReviewTarget,
  type PhotoTakedown,
  type ReportedPhotoRow,
  type StaffPhotoReviewRepository,
} from './staff-photo-review.repository';

/** The closed set of audit actions this feature writes. */
export const STAFF_PHOTO_REVIEW_AUDIT_ACTIONS = {
  APPROVED: 'profile.photo.approved',
  REJECTED: 'profile.photo.rejected',
  REMOVED: 'profile.photo.removed',
} as const;

export type StaffPhotoReviewAuditAction =
  (typeof STAFF_PHOTO_REVIEW_AUDIT_ACTIONS)[keyof typeof STAFF_PHOTO_REVIEW_AUDIT_ACTIONS];

/** Every outcome this feature can write to a photo, including a takedown. */
export type PhotoReviewOutcome = 'APPROVED' | 'REJECTED' | 'REMOVED';

const AUDIT_TARGET_TYPE = 'profile_photo';

export interface PhotoReviewQueueInput {
  readonly limit?: number;
  /** The `id` of the previous page's last row. */
  readonly cursor?: string;
}

/** One queue row, exactly as it leaves the API. */
export interface PhotoReviewQueueItem {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly caption: string | null;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly createdAt: string;
}

export interface PhotoReviewQueuePage {
  readonly items: PhotoReviewQueueItem[];
  /** `null` on the last page; otherwise the id to pass back as `cursor`. */
  readonly nextCursor: string | null;
}

export interface PhotoReviewDecisionRequest {
  readonly status: 'APPROVED' | 'REJECTED';
  /** Optional and only meaningful for a rejection. Stored in the audit metadata. */
  readonly reason?: string | null;
}

/** The whole answer a decision produces: no profile data and no reason echo. */
export interface PhotoReviewDecisionResult {
  readonly status: 'APPROVED' | 'REJECTED';
  readonly reviewedAt: string;
}

/** The whole answer a takedown produces: the photo is out of public view. */
export interface PhotoTakedownResult {
  readonly status: 'REMOVED';
  readonly reviewedAt: string;
}

export interface PhotoTakedownRequest {
  /** Optional reviewer's words; audit metadata only, never stored on the photo. */
  readonly reason?: string | null;
}

export interface ReportedPhotosInput {
  /** One-based page number over the reported list. */
  readonly page?: number;
  readonly limit?: number;
}

/** One reported photo, exactly as it leaves the API. No reporter data. */
export interface ReportedPhotoItem {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly caption: string | null;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly createdAt: string;
  readonly reportCount: number;
  readonly lastReportedAt: string;
}

export interface ReportedPhotosPage {
  readonly items: ReportedPhotoItem[];
  /** `null` on the last page; otherwise the next page number. */
  readonly nextPage: number | null;
}

/**
 * A reason is one trimmed sentence or nothing. The DTO already enforces the
 * length on the wire; the service checks it again because the same call is
 * reachable from tests and future callers.
 */
function normalizeReason(reason: string | null | undefined): string | null {
  if (typeof reason !== 'string') return null;

  const text = reason.trim();

  // Too long is a malformed field, exactly like the DTO's answer.
  if (text.length > MAX_PHOTO_REJECTION_REASON_LENGTH) throw new BadRequestException();

  return text.length === 0 ? null : text;
}

/** Same shape as a rejection reason, but for the takedown's audit metadata. */
function normalizeTakedownReason(reason: string | null | undefined): string | null {
  if (typeof reason !== 'string') return null;

  const text = reason.trim();

  // Too long is a malformed field, exactly like the DTO's answer.
  if (text.length > MAX_PHOTO_TAKEDOWN_REASON_LENGTH) throw new BadRequestException();

  return text.length === 0 ? null : text;
}

@Injectable()
export class StaffPhotoReviewService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(STAFF_PHOTO_REVIEW_REPOSITORY)
    private readonly photos: StaffPhotoReviewRepository,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * One page of PENDING photos, oldest first. The repository returns one row more
   * than the page, which is how the next cursor is known without a second query.
   */
  async listQueue(query: PhotoReviewQueueInput): Promise<PhotoReviewQueuePage> {
    const limit = query.limit ?? DEFAULT_PHOTO_REVIEW_PAGE_SIZE;
    const rows = await this.photos.listPending(limit, query.cursor);
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];

    return {
      items: page.map((row) => ({
        id: row.id,
        athleteProfileId: row.athleteProfileId,
        caption: row.caption,
        contentType: row.contentType,
        sizeBytes: row.sizeBytes,
        createdAt: row.createdAt.toISOString(),
      })),
      nextCursor: rows.length > limit && last !== undefined ? last.id : null,
    };
  }

  /**
   * Records one decision. A reviewer may not decide on a photo of their own
   * profile, and the refusal is the generic 403 with no detail.
   */
  async decide(
    actor: PolicySubject,
    photoId: string,
    decision: PhotoReviewDecisionRequest,
    context: AccessPolicyContext,
  ): Promise<PhotoReviewDecisionResult> {
    const reason = decision.status === 'REJECTED' ? normalizeReason(decision.reason) : null;
    const target = await this.photos.findForReview(photoId);

    // A missing row and an unreadable one are the same generic 404.
    if (target === null) throw new NotFoundException();

    if (target.ownerUserId === actor.id) {
      this.logger.warn(
        { requestId: context.requestId, photoId },
        'staff photo review refused: self review',
      );

      throw new ForbiddenException();
    }

    // A decision that is no longer available is answered before anything is written.
    if (target.status !== 'PENDING') throw new ConflictException();

    const reviewedAt = this.clock();

    await this.prisma.$transaction(
      async (tx) => {
        const changed = await this.photos.applyDecision(
          photoId,
          { status: decision.status, reviewedAt, reviewedById: actor.id },
          tx,
        );

        // The predicate lost between the read above and this statement: another
        // reviewer decided first. Nothing is written, and the rollback keeps it so.
        if (changed !== 1) throw new ConflictException();

        await this.record(decision.status, actor, target, reason, context, tx);
      },
      { maxWait: 5_000, timeout: 10_000 },
    );

    return { status: decision.status, reviewedAt: reviewedAt.toISOString() };
  }

  /**
   * Takes a photo out of public view: PENDING or APPROVED becomes REMOVED, the
   * encrypted blob and every other column stay. The caller is a staff principal
   * by guard, a reviewer may not remove a photo of their own profile, and a
   * photo that is already REJECTED or REMOVED is the generic 409.
   */
  async takeDown(
    actor: PolicySubject,
    photoId: string,
    request: PhotoTakedownRequest,
    context: AccessPolicyContext,
  ): Promise<PhotoTakedownResult> {
    const reason = normalizeTakedownReason(request.reason);
    const target = await this.photos.findForReview(photoId);

    // A missing row and an unreadable one are the same generic 404.
    if (target === null) throw new NotFoundException();

    if (target.ownerUserId === actor.id) {
      this.logger.warn(
        { requestId: context.requestId, photoId },
        'staff photo review refused: self takedown',
      );

      throw new ForbiddenException();
    }

    // A removal that is no longer available is answered before anything is written.
    if (target.status !== 'PENDING' && target.status !== 'APPROVED') {
      throw new ConflictException();
    }

    const reviewedAt = this.clock();
    const takedown: PhotoTakedown = { reviewedAt, reviewedById: actor.id };

    await this.prisma.$transaction(
      async (tx) => {
        const changed = await this.photos.takeDown(photoId, takedown, tx);

        // The predicate lost between the read above and this statement: another
        // reviewer decided or removed first. Nothing is written, and the rollback
        // keeps it so.
        if (changed !== 1) throw new ConflictException();

        await this.record('REMOVED', actor, target, reason, context, tx);
      },
      { maxWait: 5_000, timeout: 10_000 },
    );

    return { status: 'REMOVED', reviewedAt: reviewedAt.toISOString() };
  }

  /**
   * One page of APPROVED photos that carry reports, newest activity first. The
   * repository returns one row more than the page, which is how the next page is
   * known without a second query. There is deliberately no reporter identity, no
   * reason and no note here: the list says that a photo was reported, by nobody
   * in particular, until a reviewer opens it.
   */
  async listReported(query: ReportedPhotosInput): Promise<ReportedPhotosPage> {
    const limit = query.limit ?? DEFAULT_PHOTO_REVIEW_PAGE_SIZE;
    const page = Math.max(1, query.page ?? 1);
    const rows: ReportedPhotoRow[] = await this.photos.listReported(limit, (page - 1) * limit);
    const items = rows.slice(0, limit);

    return {
      items: items.map((row) => ({
        id: row.id,
        athleteProfileId: row.athleteProfileId,
        caption: row.caption,
        contentType: row.contentType,
        sizeBytes: row.sizeBytes,
        createdAt: row.createdAt.toISOString(),
        reportCount: row.reportCount,
        lastReportedAt: row.lastReportedAt.toISOString(),
      })),
      nextPage: rows.length > limit ? page + 1 : null,
    };
  }

  /**
   * Fail closed: the decision and its trail share one transaction, so a trail
   * that cannot be written rolls the decision back rather than report a decision
   * nobody can account for.
   *
   * The metadata is ids and names only. The reviewer's own words are the single
   * free-text field, and they exist only here - the photo row has no reason
   * column - never a caption, a key or an address.
   */
  private async record(
    status: PhotoReviewOutcome,
    actor: PolicySubject,
    target: PhotoReviewTarget,
    reason: string | null,
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    const action = STAFF_PHOTO_REVIEW_AUDIT_ACTIONS[status];

    try {
      await this.audit.record(
        {
          action,
          actorId: actor.id,
          actorRole: String(actor.role),
          targetType: AUDIT_TARGET_TYPE,
          targetId: target.id,
          requestId: context.requestId,
          ip: context.ip,
          metadata: {
            photoId: target.id,
            athleteProfileId: target.athleteProfileId,
            status,
            ...(reason === null ? {} : { reason }),
          },
        },
        tx,
      );
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'staff photo review audit failed');

      throw new ServiceUnavailableException();
    }
  }
}
