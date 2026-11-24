import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import type {
  PhotoReportInput,
  ProfilePhotoReportRepository,
  ReportablePhoto,
} from './profile-photo-report.repository';
import type { ProfilePhotoStatus } from './profile-photo.repository';

/** Prisma reports a violation of the unique pair as P2002. */
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code: unknown }).code === 'P2002'
    : false;
}

@Injectable()
export class PrismaProfilePhotoReportRepository implements ProfilePhotoReportRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findReportablePhoto(photoId: string): Promise<ReportablePhoto | null> {
    const row = await this.prisma.profilePhoto.findUnique({
      where: { id: photoId },
      select: { id: true, status: true, athleteProfile: { select: { userId: true } } },
    });

    if (row === null) return null;

    return {
      id: row.id,
      status: row.status as ProfilePhotoStatus,
      ownerUserId: row.athleteProfile.userId,
    };
  }

  async create(report: PhotoReportInput): Promise<boolean> {
    try {
      await this.prisma.photoReport.create({
        data: {
          photoId: report.photoId,
          reporterUserId: report.reporterUserId,
          reason: report.reason,
          note: report.note,
        },
      });

      return true;
    } catch (error) {
      // The second report for the same photo is not an error the caller may see.
      if (isUniqueViolation(error)) return false;

      throw error;
    }
  }
}
