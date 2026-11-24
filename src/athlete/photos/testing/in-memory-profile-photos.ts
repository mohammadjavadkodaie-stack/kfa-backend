import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import type {
  ProfilePhotoInsert,
  ProfilePhotoRecord,
  ProfilePhotoRepository,
  ProfilePhotoStatus,
} from '../profile-photo.repository';

/**
 * The `profile_photos` table without PostgreSQL, for the photo specs.
 *
 * It keeps the guarantees the service leans on - a row is written once, a new row
 * is always PENDING, only PENDING and APPROVED rows consume the quota, and a read
 * is scoped to one profile - and nothing else: the CHECK constraints belong to
 * the database and are proved by the migration review.
 */
export class InMemoryProfilePhotos implements ProfilePhotoRepository {
  private readonly rowsById = new Map<string, ProfilePhotoRecord>();
  /** Every insert attempt, in order, so a refused upload can be shown to write nothing. */
  readonly inserts: ProfilePhotoRecord[] = [];
  /** The profile of every quota read, in order. */
  readonly counts: string[] = [];
  /** Every owner list read, with the cap it asked for, in order. */
  readonly lists: { athleteProfileId: string; limit: number }[] = [];
  /** Every single-photo read, with the profile it was scoped to, in order. */
  readonly reads: { photoId: string; athleteProfileId: string }[] = [];
  /** The client each insert went through; `undefined` when the call had none. */
  readonly transactions: (Prisma.TransactionClient | undefined)[] = [];

  get rows(): ProfilePhotoRecord[] {
    return [...this.rowsById.values()];
  }

  async insert(
    record: ProfilePhotoInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord> {
    this.transactions.push(tx);

    // The column default: an upload can only ever produce PENDING, and the review
    // columns stay empty until a reviewer decides.
    const row: ProfilePhotoRecord = {
      ...record,
      id: randomUUID(),
      status: 'PENDING',
      createdAt: new Date(),
      reviewedAt: null,
      reviewedById: null,
    };

    this.rowsById.set(row.id, row);
    this.inserts.push(row);

    return row;
  }

  async countAgainstQuota(
    athleteProfileId: string,
    _tx?: Prisma.TransactionClient,
  ): Promise<number> {
    this.counts.push(athleteProfileId);

    return this.rows.filter(
      (row) => row.athleteProfileId === athleteProfileId && row.status !== 'REJECTED',
    ).length;
  }

  async listByProfile(
    athleteProfileId: string,
    limit: number,
    _tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord[]> {
    this.lists.push({ athleteProfileId, limit });

    // Same predicate and total order as the query: own rows only, newest first,
    // the id breaking a tie, at most `limit` rows.
    return this.rows
      .filter((row) => row.athleteProfileId === athleteProfileId)
      .sort(
        (left, right) =>
          right.createdAt.getTime() - left.createdAt.getTime() || right.id.localeCompare(left.id),
      )
      .slice(0, limit);
  }

  async findByProfile(
    photoId: string,
    athleteProfileId: string,
    _tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord | null> {
    this.reads.push({ photoId, athleteProfileId });

    const row = this.rowsById.get(photoId);

    // The query has both ids in the predicate: a foreign row is not found.
    return row === undefined || row.athleteProfileId !== athleteProfileId ? null : row;
  }

  /** The committed state a rollback has to bring back. */
  snapshot(): Map<string, ProfilePhotoRecord> {
    return new Map(this.rowsById);
  }

  restore(snapshot: Map<string, ProfilePhotoRecord>): void {
    this.rowsById.clear();
    snapshot.forEach((row, id) => this.rowsById.set(id, row));
  }

  /** Puts one row on a profile at a chosen time, for the quota and list checks. */
  seed(
    athleteProfileId: string,
    status: ProfilePhotoStatus = 'PENDING',
    createdAt: Date = new Date(),
  ): ProfilePhotoRecord {
    const id = randomUUID();
    const row: ProfilePhotoRecord = {
      id,
      athleteProfileId,
      objectKey: randomUUID(),
      caption: null,
      status,
      contentType: 'image/png',
      sizeBytes: 1_024,
      sha256: '9f'.repeat(32),
      keyId: 'v1',
      wrappedDek: Buffer.alloc(61, 1),
      iv: Buffer.alloc(12, 2),
      authTag: Buffer.alloc(16, 3),
      createdAt,
      reviewedAt: status === 'PENDING' ? null : createdAt,
      reviewedById: status === 'PENDING' ? null : randomUUID(),
    };

    this.rowsById.set(id, row);

    return row;
  }
}
