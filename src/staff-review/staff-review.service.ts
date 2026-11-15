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
import { AuditService } from '../audit/audit.service';
import { CLOCK, type Clock } from '../athlete/profile/athlete-age';
import {
  ATHLETE_PROFILE_REPOSITORY,
  type AthleteProfileRecord,
  type AthleteProfileRepository,
  type ReviewStatus,
} from '../athlete/profile/athlete-profile.repository';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { PROFILE_WRONG_STATE_CODE } from '../common/errors/error-response';
import { PrismaService } from '../database/prisma.service';
import type { DocumentKind } from '../documents/records/identity-document.repository';
import { DEFAULT_REVIEW_PAGE_SIZE, MAX_REJECTION_REASON_LENGTH } from './staff-review.dto';
import { REVIEW_RESULT_NOTIFIER, type ReviewResultNotifier } from './review-result-notifier';
import {
  STAFF_REVIEW_REPOSITORY,
  type ReviewRecipient,
  type StaffReviewRepository,
} from './staff-review.repository';

/** The closed set of audit actions a decision writes. */
export const STAFF_REVIEW_AUDIT_ACTIONS = {
  APPROVED: 'ATHLETE_PROFILE_APPROVED',
  REJECTED: 'ATHLETE_PROFILE_REJECTED',
} as const;

export type StaffReviewAuditAction =
  (typeof STAFF_REVIEW_AUDIT_ACTIONS)[keyof typeof STAFF_REVIEW_AUDIT_ACTIONS];

const AUDIT_TARGET_TYPE = 'athlete_profile';

/** The two outcomes a reviewer can record. There is no third. */
export type ReviewDecisionStatus = 'APPROVED' | 'REJECTED';

export interface ReviewQueueInput {
  readonly status?: ReviewStatus;
  readonly limit?: number;
  /** The `profileId` of the previous page's last row. */
  readonly cursor?: string;
}

/**
 * One row of the queue. `profileId` is the profile's owner id and the only id a
 * reviewer ever gets: no name, no address, no phone number reach this payload.
 */
export interface ReviewQueueItem {
  readonly profileId: string;
  readonly reviewStatus: ReviewStatus;
  readonly submittedAt: string | null;
  /** ACTIVE documents only: a deleted row is not evidence. */
  readonly documentCount: number;
}

export interface ReviewQueuePage {
  readonly items: ReviewQueueItem[];
  /** `null` on the last page; otherwise the id to pass back as `cursor`. */
  readonly nextCursor: string | null;
}

/** Metadata of one document. The bytes stay behind the view-link flow. */
export interface ReviewDocumentView {
  readonly id: string;
  readonly kind: DocumentKind;
  readonly sizeBytes: number;
  readonly createdAt: string;
}

export interface ReviewDetailView {
  readonly profileId: string;
  readonly reviewStatus: ReviewStatus;
  readonly submittedAt: string | null;
  readonly reviewedAt: string | null;
  /** The reviewer's own text, kept so a colleague sees why it was refused. */
  readonly rejectionReason: string | null;
  readonly documents: ReviewDocumentView[];
}

export interface ReviewDecisionRequest {
  readonly status: ReviewDecisionStatus;
  /** Required for a rejection, ignored for an approval. */
  readonly reason?: string | null;
}

/** The whole answer a decision produces: no reason echo, no profile data. */
export interface ReviewDecisionResult {
  readonly reviewStatus: ReviewDecisionStatus;
  readonly reviewedAt: string;
}

/**
 * A reason is one trimmed sentence or nothing. The DTO already enforces this on
 * the wire; the service checks it again because a rejection without a reason
 * tells the athlete nothing about what to fix.
 */
function normalizeReason(
  status: ReviewDecisionStatus,
  reason: string | null | undefined,
): string | null {
  if (status === 'APPROVED') return null;

  const text = typeof reason === 'string' ? reason.trim() : '';

  if (text.length === 0 || text.length > MAX_REJECTION_REASON_LENGTH) {
    // Generic 400: the client learns the shape of the field, not the rule set.
    throw new BadRequestException();
  }

  return text;
}

/**
 * The staff review queue and its two decisions.
 *
 * Reads are metadata only: the queue names profiles by id and counts their live
 * documents, the detail page adds those documents' metadata, and the content
 * itself stays behind the step-up-gated view-link route. Decisions are a single
 * conditional UPDATE - a profile leaves PENDING once - and the decision, its
 * audit row and the athlete's email are ordered so that the email can fail
 * without undoing anything.
 */
@Injectable()
export class StaffReviewService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(ATHLETE_PROFILE_REPOSITORY) private readonly profiles: AthleteProfileRepository,
    @Inject(STAFF_REVIEW_REPOSITORY) private readonly reviews: StaffReviewRepository,
    @Inject(REVIEW_RESULT_NOTIFIER) private readonly notifier: ReviewResultNotifier,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * One page of the queue, oldest submission first. The repository returns one
   * row more than the page, which is how the next cursor is known without a
   * second query and without an exact-count scan.
   */
  async listQueue(query: ReviewQueueInput): Promise<ReviewQueuePage> {
    const status = query.status ?? 'PENDING';
    const limit = query.limit ?? DEFAULT_REVIEW_PAGE_SIZE;

    const rows = await this.profiles.listForReview({
      status,
      limit,
      ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
    });

    const page = rows.slice(0, limit);
    const counts = await this.reviews.countActiveDocuments(page.map((row) => row.userId));
    const last = page[page.length - 1];

    return {
      items: page.map((row) => ({
        profileId: row.userId,
        reviewStatus: row.reviewStatus,
        submittedAt: row.submittedAt?.toISOString() ?? null,
        documentCount: counts.get(row.userId) ?? 0,
      })),
      nextCursor: rows.length > limit && last !== undefined ? last.userId : null,
    };
  }

  /** One submitted profile: its state and its documents' metadata, nothing else. */
  async readDetail(profileId: string): Promise<ReviewDetailView> {
    const record = await this.findSubmitted(profileId);
    const documents = await this.reviews.listActiveDocuments(record.userId);

    return {
      profileId: record.userId,
      reviewStatus: record.reviewStatus,
      submittedAt: record.submittedAt?.toISOString() ?? null,
      reviewedAt: record.reviewedAt?.toISOString() ?? null,
      rejectionReason: record.rejectionReason,
      documents: documents.map((document) => ({
        id: document.id,
        kind: document.kind,
        sizeBytes: document.sizeBytes,
        createdAt: document.createdAt.toISOString(),
      })),
    };
  }

  /**
   * Records one decision, then tells the athlete.
   *
   * A reviewer may not decide on their own profile: the queue is a second pair
   * of eyes. The refusal is the generic 403 with no detail, so the queue cannot
   * be probed through it.
   */
  async decide(
    actor: PolicySubject,
    profileId: string,
    decision: ReviewDecisionRequest,
    context: AccessPolicyContext,
  ): Promise<ReviewDecisionResult> {
    const reason = normalizeReason(decision.status, decision.reason);

    if (profileId === actor.id) {
      this.logger.warn(
        { requestId: context.requestId, profileId },
        'staff review refused: self review',
      );

      throw new ForbiddenException();
    }

    const record = await this.findSubmitted(profileId);

    // A decision that is no longer available is a 409 the client can recognise,
    // and it is answered before anything is written.
    if (record.reviewStatus !== 'PENDING') throw this.wrongState();

    const reviewedAt = this.clock();

    await this.prisma.$transaction(
      async (tx) => {
        const changed = await this.profiles.applyReviewDecision(
          record.userId,
          {
            status: decision.status,
            reviewedAt,
            reviewedById: actor.id,
            rejectionReason: reason,
          },
          tx,
        );

        // The predicate lost between the check above and this statement: another
        // reviewer decided first. Nothing is written, and the rollback keeps it so.
        if (changed !== 1) throw this.wrongState();

        await this.record(decision.status, actor, record.userId, reason, context, tx);
      },
      { maxWait: 5_000, timeout: 10_000 },
    );

    await this.notify(record.userId, decision.status, reason, context);

    return { reviewStatus: decision.status, reviewedAt: reviewedAt.toISOString() };
  }

  /**
   * A profile enters the queue only by being submitted. Anything else - a row
   * that does not exist and a draft that was never sent - gets the same 404, so
   * a reviewer cannot learn which accounts are halfway through a form.
   */
  private async findSubmitted(profileId: string): Promise<AthleteProfileRecord> {
    const record = await this.profiles.findByUserId(profileId);

    if (record === null || record.submittedAt === null) throw new NotFoundException();

    return record;
  }

  private wrongState(): ConflictException {
    return new ConflictException({ code: PROFILE_WRONG_STATE_CODE });
  }

  /**
   * The decision and its trail share one transaction, fail-closed like the admin
   * routes: a decision nobody can account for is not recorded at all.
   */
  private async record(
    status: ReviewDecisionStatus,
    actor: PolicySubject,
    profileId: string,
    reason: string | null,
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    const action = STAFF_REVIEW_AUDIT_ACTIONS[status];

    try {
      await this.audit.record(
        {
          action,
          actorId: actor.id,
          actorRole: String(actor.role),
          targetType: AUDIT_TARGET_TYPE,
          targetId: profileId,
          requestId: context.requestId,
          ip: context.ip,
          // The reviewer's words only; the profile itself is never copied here.
          metadata: reason === null ? {} : { reason },
        },
        tx,
      );
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'staff review audit failed');

      throw new ServiceUnavailableException();
    }
  }

  /**
   * Best effort, after the commit. Every failure is a warning with a request id
   * and the outcome - never an address - and never a rollback: the decision
   * already happened and the reviewer has to see it.
   */
  private async notify(
    profileId: string,
    status: ReviewDecisionStatus,
    reason: string | null,
    context: AccessPolicyContext,
  ): Promise<void> {
    let recipient: ReviewRecipient | null;

    try {
      recipient = await this.reviews.findRecipient(profileId);
    } catch {
      this.logger.warn(
        { requestId: context.requestId, profileId, status },
        'review decision email skipped: recipient unreadable',
      );

      return;
    }

    const address = recipient?.email ?? null;

    if (address === null || address.length === 0) {
      this.logger.warn(
        { requestId: context.requestId, profileId, status },
        'review decision email skipped: no address on file',
      );

      return;
    }

    try {
      await this.notifier.sendResult({
        to: address,
        status,
        reason,
      });
    } catch {
      this.logger.warn(
        { requestId: context.requestId, profileId, status },
        'review decision email failed',
      );
    }
  }
}
