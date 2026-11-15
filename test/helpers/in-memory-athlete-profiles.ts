import type { Prisma } from '@prisma/client';
import type {
  AthleteProfileInput,
  AthleteProfileRecord,
  AthleteProfileRepository,
} from '../../src/athlete/profile/athlete-profile.repository';

/**
 * The athlete profile table without PostgreSQL, for the API suites.
 *
 * It keeps the one guarantee the service leans on - one row per user, replaced
 * wholesale - and nothing else: the CHECK constraints belong to the database and
 * are proved by the database suites, while the DTO is proved by the pipe.
 */
export class InMemoryAthleteProfileRepository implements AthleteProfileRepository {
  readonly rows = new Map<string, AthleteProfileRecord>();
  /** Every write, in order, so a refused request can be shown to have written nothing. */
  readonly writes: { userId: string; data: AthleteProfileInput }[] = [];

  async findByUserId(userId: string): Promise<AthleteProfileRecord | null> {
    return this.rows.get(userId) ?? null;
  }

  async submitForReview(
    userId: string,
    submittedAt: Date,
    _tx?: Prisma.TransactionClient,
  ): Promise<number> {
    const row = this.rows.get(userId);
    if (row === undefined || !['DRAFT', 'REJECTED'].includes(row.reviewStatus)) return 0;
    this.rows.set(userId, { ...row, reviewStatus: 'PENDING', submittedAt, rejectionReason: null });
    return 1;
  }

  async upsertForUser(
    userId: string,
    data: AthleteProfileInput,
    // The map is the whole store, so there is no client to write through here.
    _tx?: Prisma.TransactionClient,
  ): Promise<AthleteProfileRecord> {
    this.writes.push({ userId, data });

    const previous = this.rows.get(userId);
    const now = new Date();
    const next: AthleteProfileRecord = {
      userId,
      ...data,
      clubName: data.clubName ?? null,
      weightKg: data.weightKg ?? null,
      heightCm: data.heightCm ?? null,
      createdAt: previous?.createdAt ?? now,
      updatedAt: now,
      reviewStatus: previous?.reviewStatus ?? 'DRAFT',
      submittedAt: previous?.submittedAt ?? null,
      reviewedAt: previous?.reviewedAt ?? null,
      reviewedById: previous?.reviewedById ?? null,
      rejectionReason: previous?.rejectionReason ?? null,
    };

    this.rows.set(userId, next);

    return next;
  }
}
