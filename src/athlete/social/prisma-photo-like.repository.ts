import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import type { ProfilePhotoStatus } from '../photos/profile-photo.repository';
import type { LikeablePhoto, PhotoLikeRepository } from './photo-like.repository';

/** Prisma reports a violation of the unique pair as P2002. */
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code: unknown }).code === 'P2002'
    : false;
}

@Injectable()
export class PrismaPhotoLikeRepository implements PhotoLikeRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findPhoto(photoId: string): Promise<LikeablePhoto | null> {
    const row = await this.prisma.profilePhoto.findUnique({
      where: { id: photoId },
      select: { id: true, status: true, athleteProfile: { select: { userId: true } } },
    });

    if (row === null) return null;

    return {
      id: row.id,
      status: row.status as ProfilePhotoStatus,
      userId: row.athleteProfile.userId,
    };
  }

  async create(photoId: string, userId: string): Promise<boolean> {
    try {
      await this.prisma.photoLike.create({ data: { photoId, userId } });

      return true;
    } catch (error) {
      // Liking twice is not an error the caller may see.
      if (isUniqueViolation(error)) return false;

      throw error;
    }
  }

  async remove(photoId: string, userId: string): Promise<number> {
    const removed = await this.prisma.photoLike.deleteMany({ where: { photoId, userId } });

    return removed.count;
  }

  count(photoId: string): Promise<number> {
    return this.prisma.photoLike.count({ where: { photoId } });
  }
}
