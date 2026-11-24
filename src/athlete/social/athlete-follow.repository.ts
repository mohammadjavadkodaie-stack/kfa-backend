/**
 * The storage seam behind a follow.
 *
 * A follow is one row per (follower, followed profile): the unique pair is
 * enforced by the database, and this interface turns a duplicate insert into a
 * plain `false`, so a repeated PUT is indistinguishable from the first one.
 * Nothing here ever returns a list of followers or a follower id.
 */

/** DI token so the Prisma implementation can be swapped in tests. */
export const ATHLETE_FOLLOW_REPOSITORY = Symbol('ATHLETE_FOLLOW_REPOSITORY');

/** The only facts a follow needs from its target. */
export interface FollowableProfile {
  readonly id: string;
  /** The account the profile belongs to; the one person who may not follow it. */
  readonly userId: string;
}

export interface AthleteFollowRepository {
  /**
   * The profile only when the public may see it, meaning an APPROVED resume. A
   * missing row, a DRAFT one, a PENDING one and a REJECTED one are all `null`.
   */
  findPublicProfile(profileId: string): Promise<FollowableProfile | null>;

  /**
   * Inserts one follow. Returns `false` when the same pair already existed - the
   * unique pair, not a read-then-write, is what decides.
   */
  create(followerUserId: string, followedProfileId: string): Promise<boolean>;

  /** Removes the pair; 0 when the caller was not following. */
  remove(followerUserId: string, followedProfileId: string): Promise<number>;

  /** How many accounts follow one profile. Never who they are. */
  countFollowers(followedProfileId: string): Promise<number>;

  /** Whether this viewer already follows the profile. */
  isFollowing(followerUserId: string, followedProfileId: string): Promise<boolean>;
}
