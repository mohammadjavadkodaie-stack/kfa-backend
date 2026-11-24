import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import type { AthleteFollowRepository, FollowableProfile } from './athlete-follow.repository';

/** Prisma reports a violation of the unique pair as P2002. */
function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code: unknown }).code === 'P2002'
    : false;
}

@Injectable()
export class PrismaAthleteFollowRepository implements AthleteFollowRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findPublicProfile(profileId: string): Promise<FollowableProfile | null> {
    return this.prisma.athleteProfile.findFirst({
      where: { id: profileId, reviewStatus: 'APPROVED' },
      select: { id: true, userId: true },
    });
  }

  async create(followerUserId: string, followedProfileId: string): Promise<boolean> {
    try {
      await this.prisma.athleteFollow.create({ data: { followerUserId, followedProfileId } });

      return true;
    } catch (error) {
      // Following twice is not an error the caller may see.
      if (isUniqueViolation(error)) return false;

      throw error;
    }
  }

  async remove(followerUserId: string, followedProfileId: string): Promise<number> {
    const removed = await this.prisma.athleteFollow.deleteMany({
      where: { followerUserId, followedProfileId },
    });

    return removed.count;
  }

  countFollowers(followedProfileId: string): Promise<number> {
    return this.prisma.athleteFollow.count({ where: { followedProfileId } });
  }

  async isFollowing(followerUserId: string, followedProfileId: string): Promise<boolean> {
    const row = await this.prisma.athleteFollow.findUnique({
      where: { followerUserId_followedProfileId: { followerUserId, followedProfileId } },
      select: { id: true },
    });

    return row !== null;
  }
}
