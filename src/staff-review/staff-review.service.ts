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
import { CLOCK, isMinor, type Clock } from '../athlete/profile/athlete-age';
import {
  ATHLETE_PROFILE_REPOSITORY,
  type AthleteProfileRecord,
  type AthleteProfileRepository,
  type Gender,
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

/** The closed set of audit actions this feature writes. */
export const STAFF_REVIEW_AUDIT_ACTIONS = {
  APPROVED: 'ATHLETE_PROFILE_APPROVED',
  REJECTED: 'ATHLETE_PROFILE_REJECTED',
  DETAIL_VIEWED: 'STAFF_REVIEW_DETAIL_VIEWED',
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
 * reviewer ever gets. The name and the nationality are what the reviewer needs to
 * tell two similar applications apart; nothing else about the person is here.
 */
export interface ReviewQueueItem {
  readonly profileId: string;
  readonly reviewStatus: ReviewStatus;
  readonly submittedAt: string | null;
  /** ACTIVE documents only: a deleted row is not evidence. */
  readonly documentCount: number;
  readonly legalFirstName: string;
  readonly legalLastName: string;
  /** ISO 3166-1 alpha-2, to compare with the document's issuing country. */
  readonly nationality: string;
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

/**
 * One submitted profile as the reviewer compares it with the identity document.
 * There is no address, no username and no id beyond the owner id already in the
 * queue: a reviewer needs the declared facts, not the account behind them.
 */
export interface ReviewDetailView {
  readonly profileId: string;
  readonly reviewStatus: ReviewStatus;
  readonly submittedAt: string | null;
  readonly reviewedAt: string | null;
  /** The reviewer's own text, kept so a colleague sees why it was refused. */
  readonly rejectionReason: string | null;
  readonly legalFirstName: string;
  readonly legalLastName: string;
  /** `YYYY-MM-DD`: a calendar day, the same shape the athlete declared. */
  readonly dateOfBirth: string;
  readonly gender: Gender;
  readonly nationality: string;
  readonly countryOfResidence: string;
  readonly city: string;
  readonly clubName: string | null;
  readonly weightKg: number | null;
  readonly heightCm: number | null;
  /** Derived from the birthday and the clock; the row does not hold it. */
  readonly isMinor: boolean;
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
 * The queue carries the declared name and nationality next to the document count,
 * and the detail page adds the rest of what the athlete declared so it can be
 * compared with the identity card. The document content itself stays behind the
 * step-up-gated view-link route, and every detail read is audited. Decisions are
 * a single conditional UPDATE - a profile leaves PENDING once - and the decision,
 * its audit row and the athlete's email are ordered so that the email can fail
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
        legalFirstName: row.legalFirstName,
        legalLastName: row.legalLastName,
        nationality: row.nationality,
      })),
      nextCursor: rows.length > limit && last !== undefined ? last.userId : null,
    };
  }

  /**
   * One submitted profile: the declared data a reviewer compares with the
   * document, plus the documents' metadata. No address, no username and no
   * content. Every successful read leaves a trail row, and a trail that cannot
   * be written fails the read closed.
   */
  async readDetail(
    actor: PolicySubject,
    profileId: string,
    context: AccessPolicyContext,
  ): Promise<ReviewDetailView> {
    const record = await this.findSubmitted(profileId);
    const documents = await this.reviews.listActiveDocuments(record.userId);

    // Before the page leaves the service: the answer is personal data and the
    // trail is what proves who looked at it.
    await this.recordDetailView(actor, record.userId, context);

    return {
      profileId: record.userId,
      reviewStatus: record.reviewStatus,
      submittedAt: record.submittedAt?.toISOString() ?? null,
      reviewedAt: record.reviewedAt?.toISOString() ?? null,
      rejectionReason: record.rejectionReason,
      legalFirstName: record.legalFirstName,
      legalLastName: record.legalLastName,
      dateOfBirth: record.dateOfBirth,
      gender: record.gender,
      nationality: record.nationality,
      countryOfResidence: record.countryOfResidence,
      city: record.city,
      clubName: record.clubName,
      weightKg: record.weightKg,
      heightCm: record.heightCm,
      isMinor: isMinor(record.dateOfBirth, this.clock()),
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
   * One trail row per successful detail read: who saw which profile, and not a
   * word about the profile itself. A read that cannot be accounted for is not
   * served, the same fail-closed rule a decision follows.
   */
  private async recordDetailView(
    actor: PolicySubject,
    profileId: string,
    context: AccessPolicyContext,
  ): Promise<void> {
    const action = STAFF_REVIEW_AUDIT_ACTIONS.DETAIL_VIEWED;

    try {
      await this.audit.record({
        action,
        actorId: actor.id,
        actorRole: String(actor.role),
        targetType: AUDIT_TARGET_TYPE,
        targetId: profileId,
        requestId: context.requestId,
        ip: context.ip,
        metadata: {},
      });
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'staff review audit failed');

      throw new ServiceUnavailableException();
    }
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
