/**
 * Following another athlete's profile.
 *
 * The order is the policy:
 *
 *   1. the caller is authenticated and active, by the global guard - a blocked
 *      account never reaches this service;
 *   2. only a profile whose resume is APPROVED is visible, so a missing id and a
 *      DRAFT, PENDING or REJECTED profile are the same generic 404;
 *   3. a caller cannot follow the profile of their own account; that refusal is
 *      the very same 404, so it says nothing about which id exists;
 *   4. a repeated follow is a silent no-op - the answer is the same 204, decided
 *      by the unique pair in the database, not by a read-then-write.
 *
 * The social read returns a count and one boolean for the viewer. It never
 * returns a follower list or a user id.
 */

import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PolicySubject } from '../../auth/policy/access-policy';
import {
  ATHLETE_FOLLOW_REPOSITORY,
  type AthleteFollowRepository,
  type FollowableProfile,
} from './athlete-follow.repository';

/** What `GET /athletes/:profileId/social` may answer. */
export interface AthleteSocialView {
  readonly followerCount: number;
  readonly viewerFollows: boolean;
}

@Injectable()
export class AthleteFollowService {
  constructor(
    @Inject(ATHLETE_FOLLOW_REPOSITORY)
    private readonly follows: AthleteFollowRepository,
  ) {}

  async follow(actor: PolicySubject, profileId: string): Promise<void> {
    const target = await this.followableTarget(actor, profileId);

    await this.follows.create(actor.id, target.id);
  }

  async unfollow(actor: PolicySubject, profileId: string): Promise<void> {
    const target = await this.followableTarget(actor, profileId);

    await this.follows.remove(actor.id, target.id);
  }

  async social(actor: PolicySubject, profileId: string): Promise<AthleteSocialView> {
    const target = await this.visibleProfile(profileId);

    const [followerCount, viewerFollows] = await Promise.all([
      this.follows.countFollowers(target.id),
      this.follows.isFollowing(actor.id, target.id),
    ]);

    return { followerCount, viewerFollows };
  }

  /** A visible target that is not the caller's own profile; never any detail. */
  private async followableTarget(
    actor: PolicySubject,
    profileId: string,
  ): Promise<FollowableProfile> {
    const target = await this.visibleProfile(profileId);

    if (target.userId === actor.id) throw new NotFoundException();

    return target;
  }

  private async visibleProfile(profileId: string): Promise<FollowableProfile> {
    const target = await this.follows.findPublicProfile(profileId);

    if (target === null) throw new NotFoundException();

    return target;
  }
}
