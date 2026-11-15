/**
 * Persistence boundary for the staff review queue.
 *
 * The queue reads profiles, document counts and document metadata - and nothing
 * else. No method here returns a name, a storage object key or document bytes:
 * the reviewer works from the view-link flow for content, and the athlete's
 * legal name never reaches this feature at all.
 */

import type { DocumentKind } from '../documents/records/identity-document.repository';

/** The document columns a reviewer may see: never the object key, never the content. */
export interface ReviewDocumentMetadata {
  readonly id: string;
  readonly kind: DocumentKind;
  readonly sizeBytes: number;
  readonly createdAt: Date;
}

/**
 * Where the decision email goes. The address is the only field: the product has
 * no stored language preference yet, so the message is written in the default
 * language of the templates, exactly like every other transactional email.
 */
export interface ReviewRecipient {
  readonly email: string | null;
}

/** DI token so the Prisma implementation can be swapped in tests. */
export const STAFF_REVIEW_REPOSITORY = Symbol('STAFF_REVIEW_REPOSITORY');

export interface StaffReviewRepository {
  /**
   * ACTIVE documents per profile id, in one grouped query, so a list page can
   * show counts without a query per row. Owners with none are simply absent.
   */
  countActiveDocuments(ownerUserIds: readonly string[]): Promise<ReadonlyMap<string, number>>;
  /** The ACTIVE documents of one profile, newest first, metadata only. */
  listActiveDocuments(ownerUserId: string): Promise<ReviewDocumentMetadata[]>;
  /** The decision email's target row; `null` when the profile is gone. */
  findRecipient(profileId: string): Promise<ReviewRecipient | null>;
}
