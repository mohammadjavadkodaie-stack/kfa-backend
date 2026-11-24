import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../database/prisma.service';
import {
  PROFILE_PHOTO_RECORD_FIELDS,
  toProfilePhotoRecord,
} from './prisma-profile-photo.repository';
import type { PhotoContentType } from './profile-photo.repository';
import type {
  ApprovedPhotoSummary,
  ProfilePhotoViewRecord,
  ProfilePhotoViewRepository,
} from './profile-photo-view.repository';

/**
 * The columns a public listing may carry: metadata only — never the object
 * key, the envelope or the digest.
 */
const APPROVED_FIELDS = {
  id: true,
  caption: true,
  contentType: true,
  sizeBytes: true,
  createdAt: true,
} as const;

type ApprovedRow = Prisma.ProfilePhotoGetPayload<{ select: typeof APPROVED_FIELDS }>;

/**
 * Prisma-backed read model for serving profile photos. It exists so the view
 * stack can fetch a row with its owner in one query and never touch the
 * upload-side queries.
 */
@Injectable()
export class PrismaProfilePhotoViewRepository implements ProfilePhotoViewRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(photoId: string): Promise<ProfilePhotoViewRecord | null> {
    const row = await this.prisma.profilePhoto.findUnique({
      where: { id: photoId },
      // The full record (envelope included): the caller decides what may be
      // served, and the bytes cannot be decrypted without these columns.
      select: { ...PROFILE_PHOTO_RECORD_FIELDS, athleteProfile: { select: { userId: true } } },
    });

    if (row === null) return null;

    const { athleteProfile, ...photo } = row;
    return { photo: toProfilePhotoRecord(photo), ownerUserId: athleteProfile.userId };
  }

  async listApproved(
    athleteProfileId: string,
    limit: number,
    cursor?: string,
  ): Promise<ApprovedPhotoSummary[]> {
    // A total order (time, then the unique id) makes the answer stable between
    // two reads; the cursor page resumes at exactly the row it was handed. The
    // `APPROVED` predicate is part of the query: a row that lost its status
    // drops out of the listing on the next read, cursor or not.
    const rows: ApprovedRow[] = await this.prisma.profilePhoto.findMany({
      where: { athleteProfileId, status: 'APPROVED' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit,
      ...(cursor === undefined ? {} : { cursor: { id: cursor }, skip: 1 }),
      select: APPROVED_FIELDS,
    });

    return rows.map((row) => ({ ...row, contentType: row.contentType as PhotoContentType }));
  }
}
