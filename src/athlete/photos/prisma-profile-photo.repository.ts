import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../database/prisma.service';
import type {
  PhotoContentType,
  ProfilePhotoInsert,
  ProfilePhotoRecord,
  ProfilePhotoRepository,
} from './profile-photo.repository';

/** Columns the repository reads back; nothing is hidden behind a `select *`. */
export const PROFILE_PHOTO_RECORD_FIELDS = {
  id: true,
  athleteProfileId: true,
  objectKey: true,
  caption: true,
  status: true,
  contentType: true,
  sizeBytes: true,
  sha256: true,
  keyId: true,
  wrappedDek: true,
  iv: true,
  authTag: true,
  createdAt: true,
  reviewedAt: true,
  reviewedById: true,
} as const;

type PhotoRow = Prisma.ProfilePhotoGetPayload<{ select: typeof PROFILE_PHOTO_RECORD_FIELDS }>;

function toColumns(record: ProfilePhotoInsert) {
  return {
    athleteProfileId: record.athleteProfileId,
    objectKey: record.objectKey,
    caption: record.caption,
    contentType: record.contentType,
    sizeBytes: record.sizeBytes,
    sha256: record.sha256,
    keyId: record.keyId,
    // `Bytes` columns take a plain Uint8Array; a copy also keeps the caller's
    // buffer from being aliased by the client.
    wrappedDek: new Uint8Array(record.wrappedDek),
    iv: new Uint8Array(record.iv),
    authTag: new Uint8Array(record.authTag),
  };
}

/** `Bytes` columns come back as `Uint8Array`; the boundary hands out Buffers. */
export function toProfilePhotoRecord(row: PhotoRow): ProfilePhotoRecord {
  return {
    ...row,
    contentType: row.contentType as PhotoContentType,
    wrappedDek: Buffer.from(row.wrappedDek),
    iv: Buffer.from(row.iv),
    authTag: Buffer.from(row.authTag),
  };
}

@Injectable()
export class PrismaProfilePhotoRepository implements ProfilePhotoRepository {
  constructor(private readonly prisma: PrismaService) {}

  async insert(
    record: ProfilePhotoInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord> {
    // The caller's transaction when there is one: only the shared client lets
    // the row roll back together with the audit entry that describes it.
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // No `status` is written: the column default PENDING is the only value an
    // upload can produce, whatever a future caller passes in.
    const row = await client.profilePhoto.create({
      data: toColumns(record),
      select: PROFILE_PHOTO_RECORD_FIELDS,
    });

    return toProfilePhotoRecord(row);
  }

  async countAgainstQuota(
    athleteProfileId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<number> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;

    return client.profilePhoto.count({
      where: { athleteProfileId, status: { in: ['PENDING', 'APPROVED'] } },
    });
  }

  async listByProfile(
    athleteProfileId: string,
    limit: number,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord[]> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // A total order (time, then the unique id) makes the answer stable between
    // two reads of the same rows; the cap bounds what the route serializes.
    const rows = await client.profilePhoto.findMany({
      where: { athleteProfileId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit,
      select: PROFILE_PHOTO_RECORD_FIELDS,
    });

    return rows.map(toProfilePhotoRecord);
  }

  async findByProfile(
    photoId: string,
    athleteProfileId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord | null> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // Profile id is part of the predicate, never a check the caller could skip.
    const row = await client.profilePhoto.findFirst({
      where: { id: photoId, athleteProfileId },
      select: PROFILE_PHOTO_RECORD_FIELDS,
    });

    return row === null ? null : toProfilePhotoRecord(row);
  }
}
