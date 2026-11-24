import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { PhotoContentType } from '../athlete/photos/profile-photo.repository';
import { PrismaService } from '../database/prisma.service';
import type {
  PendingPhotoRow,
  PhotoReviewDecision,
  PhotoReviewTarget,
  PhotoTakedown,
  ReportedPhotoRow,
  StaffPhotoReviewRepository,
} from './staff-photo-review.repository';

/** Metadata columns only: never the object key, the envelope or the digest. */
const QUEUE_FIELDS = {
  id: true,
  athleteProfileId: true,
  caption: true,
  createdAt: true,
  contentType: true,
  sizeBytes: true,
} as const;

/** The decision target: the row's status and the account that owns it. */
const TARGET_FIELDS = {
  id: true,
  athleteProfileId: true,
  status: true,
  athleteProfile: { select: { userId: true } },
} as const;

type QueueRow = Prisma.ProfilePhotoGetPayload<{ select: typeof QUEUE_FIELDS }>;
type TargetRow = Prisma.ProfilePhotoGetPayload<{ select: typeof TARGET_FIELDS }>;

@Injectable()
export class PrismaStaffPhotoReviewRepository implements StaffPhotoReviewRepository {
  constructor(private readonly prisma: PrismaService) {}

  async listPending(limit: number, cursor?: string): Promise<PendingPhotoRow[]> {
    // A total order (time, then the unique id) makes the answer stable between
    // two reads; the cursor page resumes at exactly the row it was handed.
    const rows: QueueRow[] = await this.prisma.profilePhoto.findMany({
      where: { status: 'PENDING' },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: limit + 1,
      ...(cursor === undefined ? {} : { cursor: { id: cursor }, skip: 1 }),
      select: QUEUE_FIELDS,
    });

    return rows.map((row) => ({ ...row, contentType: row.contentType as PhotoContentType }));
  }

  async findForReview(photoId: string): Promise<PhotoReviewTarget | null> {
    const row: TargetRow | null = await this.prisma.profilePhoto.findUnique({
      where: { id: photoId },
      select: TARGET_FIELDS,
    });

    if (row === null) return null;

    return {
      id: row.id,
      athleteProfileId: row.athleteProfileId,
      ownerUserId: row.athleteProfile.userId,
      status: row.status,
    };
  }

  async applyDecision(
    photoId: string,
    decision: PhotoReviewDecision,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;

    // The predicate is the gate: PENDING is the only state a decision leaves.
    const result = await client.profilePhoto.updateMany({
      where: { id: photoId, status: 'PENDING' },
      data: {
        status: decision.status,
        reviewedAt: decision.reviewedAt,
        reviewedById: decision.reviewedById,
      },
    });

    return result.count;
  }

  async takeDown(
    photoId: string,
    takedown: PhotoTakedown,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;

    // The predicate is the gate: only a photo that is still PENDING or APPROVED
    // can be taken down, so a removal happens exactly once. The encrypted blob is
    // untouched; only the status and the review stamps change.
    const result = await client.profilePhoto.updateMany({
      where: { id: photoId, status: { in: ['PENDING', 'APPROVED'] } },
      data: {
        status: 'REMOVED',
        reviewedAt: takedown.reviewedAt,
        reviewedById: takedown.reviewedById,
      },
    });

    return result.count;
  }

  async listReported(limit: number, offset: number): Promise<ReportedPhotoRow[]> {
    // One group per photo, with the count and the newest report. The APPROVED
    // predicate is part of the query, so a taken-down photo drops out at once.
    const groups = await this.prisma.photoReport.groupBy({
      by: ['photoId'],
      where: { photo: { status: 'APPROVED' } },
      _count: { _all: true },
      _max: { createdAt: true },
      orderBy: [{ _max: { createdAt: 'desc' } }, { photoId: 'asc' }],
      skip: offset,
      // One row more than the page, so the service knows there is a next page
      // without a second query.
      take: limit + 1,
    });

    if (groups.length === 0) return [];

    const rows: QueueRow[] = await this.prisma.profilePhoto.findMany({
      where: { id: { in: groups.map((group) => group.photoId) }, status: 'APPROVED' },
      select: QUEUE_FIELDS,
    });

    const byId = new Map(rows.map((row) => [row.id, row]));

    // The group order is the page order; a row that disappeared between the two
    // reads is simply absent. No reporter id, note or reason leaves this layer.
    return groups.flatMap((group) => {
      const row = byId.get(group.photoId);

      if (row === undefined) return [];

      return [
        {
          ...row,
          contentType: row.contentType as PhotoContentType,
          reportCount: group._count._all,
          lastReportedAt: group._max.createdAt ?? row.createdAt,
        },
      ];
    });
  }
}
