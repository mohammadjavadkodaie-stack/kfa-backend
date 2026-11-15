/**
 * Persistence boundary for the athlete profile.
 *
 * The profile belongs to a user, so every operation is keyed by `userId` and the
 * row id never leaves this layer. The API surface (controller, DTOs, own-profile
 * rules) is a later step; only the two primitives below exist today.
 */

import type { Prisma } from '@prisma/client';

export type ReviewStatus = 'DRAFT' | 'PENDING' | 'APPROVED' | 'REJECTED';

/** DI token so the Prisma implementation can be swapped in tests. */
export const ATHLETE_PROFILE_REPOSITORY = Symbol('ATHLETE_PROFILE_REPOSITORY');

/**
 * Date-only string, `YYYY-MM-DD`. The column is DATE; handing a Date across the
 * boundary would let the process timezone move the birthday by a day.
 */
export type IsoDate = string;

export type Gender = 'FEMALE' | 'MALE' | 'OTHER' | 'UNDISCLOSED';

/** Everything the user may edit, minus the derived and audit columns. */
export interface AthleteProfileInput {
  readonly legalFirstName: string;
  readonly legalLastName: string;
  readonly dateOfBirth: IsoDate;
  readonly gender: Gender;
  /** ISO 3166-1 alpha-2, uppercase. */
  readonly nationality: string;
  /** ISO 3166-1 alpha-2, uppercase. */
  readonly countryOfResidence: string;
  readonly city: string;
  readonly clubName?: string | null;
  readonly weightKg?: number | null;
  readonly heightCm?: number | null;
}

/** One stored profile. `isMinor` is derived, so it is not part of the row. */
export interface AthleteProfileRecord extends Required<AthleteProfileInput> {
  readonly userId: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly reviewStatus: ReviewStatus;
  readonly submittedAt: Date | null;
  readonly reviewedAt: Date | null;
  readonly reviewedById: string | null;
  readonly rejectionReason: string | null;
}

/** The one transition a reviewer makes: a PENDING row moves once, and only out of PENDING. */
export interface ReviewDecision {
  readonly status: 'APPROVED' | 'REJECTED';
  readonly reviewedAt: Date;
  readonly reviewedById: string;
  readonly rejectionReason: string | null;
}

export interface ReviewQueueQuery {
  /** Part of the predicate, never a column the caller filters afterwards. */
  readonly status: ReviewStatus;
  /** One row more than this comes back, so the caller can tell whether a page follows. */
  readonly limit: number;
  /** The `userId` of the last row of the previous page. */
  readonly cursor?: string;
}

export interface AthleteProfileRepository {
  findByUserId(userId: string): Promise<AthleteProfileRecord | null>;
  /**
   * Inserts the profile or replaces it wholesale in one statement. The unique
   * `user_id` decides, so two concurrent first saves cannot both insert.
   *
   * A caller that already owns a transaction passes it as `tx`, so the row joins
   * the same unit of work as the audit row that describes it.
   */
  upsertForUser(
    userId: string,
    data: AthleteProfileInput,
    tx?: Prisma.TransactionClient,
  ): Promise<AthleteProfileRecord>;
  submitForReview(
    userId: string,
    submittedAt: Date,
    tx?: Prisma.TransactionClient,
  ): Promise<number>;
  /**
   * Oldest submission first, so nobody waits behind a busy queue. The cursor is
   * the previous page's last `userId`; the order is completed by that same unique
   * column, so a page never repeats or skips a row.
   */
  listForReview(query: ReviewQueueQuery): Promise<AthleteProfileRecord[]>;
  /**
   * The conditional `updateMany`: `count` is 1 only for the call that moved a
   * PENDING row, so two reviewers racing on the same profile write one decision.
   */
  applyReviewDecision(
    userId: string,
    decision: ReviewDecision,
    tx?: Prisma.TransactionClient,
  ): Promise<number>;
}
