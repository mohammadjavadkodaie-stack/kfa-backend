import { BadRequestException, NotFoundException, RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Response } from 'express';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';
import type { ProfilePhotoStatus } from '../photos/profile-photo.repository';
import { AthleteFollowController } from './athlete-follow.controller';
import type { AthleteFollowRepository, FollowableProfile } from './athlete-follow.repository';
import { AthleteFollowService, type AthleteSocialView } from './athlete-follow.service';
import { PhotoLikeController } from './photo-like.controller';
import type { LikeablePhoto, PhotoLikeRepository } from './photo-like.repository';
import { PhotoLikeService } from './photo-like.service';
import {
  FOLLOW_LIMITS,
  FOLLOW_RATE_LIMIT_SCOPES,
  PHOTO_LIKE_COUNT_LIMITS,
  PHOTO_LIKE_COUNT_RATE_LIMIT_SCOPE,
  PHOTO_LIKE_LIMITS,
  PHOTO_LIKE_RATE_LIMIT_SCOPES,
} from './social-limits';

/**
 * Stage 7c, below HTTP: an idempotent follow and like, a generic 404 for own
 * profiles, hidden profiles and every non-APPROVED photo, a takedown that stops
 * the next like, aggregate-only reads, and the per-user/per-address budgets that
 * cut a script off.
 */

const VIEWER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_USER_ID = '22222222-2222-4222-8222-222222222222';
const THIRD_USER_ID = '55555555-5555-4555-8555-555555555555';
const PROFILE_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_PROFILE_ID = '44444444-4444-4444-8444-444444444444';
const PHOTO_ID = '66666666-6666-4666-8666-666666666666';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';

const viewer: PolicySubject = { id: VIEWER_ID, role: Role.USER };
const otherUser: PolicySubject = { id: OTHER_USER_ID, role: Role.USER };
const thirdUser: PolicySubject = { id: THIRD_USER_ID, role: Role.ATHLETE };

/** The response surface the two controllers use, recording what it was told. */
class RecordingResponse {
  readonly headers = new Map<string, string>();
  statusCode = 200;

  setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  status(code: number): this {
    this.statusCode = code;
    return this;
  }
}

/** Fixed-window counters with the same semantics as the Redis limiter. */
class WindowRateLimit {
  private readonly counters = new Map<string, number>();
  readonly calls: {
    readonly scope: string;
    readonly identifier: string;
    readonly limit: number;
    readonly windowSeconds: number;
  }[] = [];

  async consume(input: {
    readonly scope: string;
    readonly identifier: string;
    readonly limit: number;
    readonly windowSeconds: number;
  }) {
    this.calls.push({ ...input });

    const key = `${input.scope}:${input.identifier}:${input.windowSeconds}`;
    const hits = (this.counters.get(key) ?? 0) + 1;

    this.counters.set(key, hits);

    const allowed = hits <= input.limit;

    return {
      allowed,
      remaining: Math.max(0, input.limit - hits),
      retryAfterSeconds: allowed ? 0 : input.windowSeconds,
    };
  }

  seed(scope: string, identifier: string, windowSeconds: number, hits: number): void {
    this.counters.set(`${scope}:${identifier}:${windowSeconds}`, hits);
  }
}

/** `athlete_follows`, with the unique pair enforced exactly as the table does. */
class InMemoryFollows implements AthleteFollowRepository {
  private readonly profiles = new Map<string, FollowableProfile>();
  private readonly hidden = new Set<string>();
  private readonly pairs = new Set<string>();

  addProfile(profileId: string, userId: string, visible = true): void {
    this.profiles.set(profileId, { id: profileId, userId });

    if (!visible) this.hidden.add(profileId);
  }

  async findPublicProfile(profileId: string): Promise<FollowableProfile | null> {
    if (this.hidden.has(profileId)) return null;

    return this.profiles.get(profileId) ?? null;
  }

  async create(followerUserId: string, followedProfileId: string): Promise<boolean> {
    const key = `${followerUserId}:${followedProfileId}`;

    if (this.pairs.has(key)) return false;

    this.pairs.add(key);

    return true;
  }

  async remove(followerUserId: string, followedProfileId: string): Promise<number> {
    return this.pairs.delete(`${followerUserId}:${followedProfileId}`) ? 1 : 0;
  }

  async countFollowers(followedProfileId: string): Promise<number> {
    return [...this.pairs].filter((key) => key.endsWith(`:${followedProfileId}`)).length;
  }

  async isFollowing(followerUserId: string, followedProfileId: string): Promise<boolean> {
    return this.pairs.has(`${followerUserId}:${followedProfileId}`);
  }
}

/** `photo_likes`, same unique pair as the table. */
class InMemoryLikes implements PhotoLikeRepository {
  private readonly photos = new Map<
    string,
    { readonly id: string; readonly status: ProfilePhotoStatus; readonly userId: string }
  >();
  private readonly pairs = new Set<string>();

  addPhoto(photoId: string, status: ProfilePhotoStatus = 'APPROVED', userId = OTHER_USER_ID): void {
    this.photos.set(photoId, { id: photoId, status, userId });
  }

  async findPhoto(photoId: string): Promise<LikeablePhoto | null> {
    return this.photos.get(photoId) ?? null;
  }

  async create(photoId: string, userId: string): Promise<boolean> {
    const key = `${photoId}:${userId}`;

    if (this.pairs.has(key)) return false;

    this.pairs.add(key);

    return true;
  }

  async remove(photoId: string, userId: string): Promise<number> {
    return this.pairs.delete(`${photoId}:${userId}`) ? 1 : 0;
  }

  async count(photoId: string): Promise<number> {
    return [...this.pairs].filter((key) => key.startsWith(`${photoId}:`)).length;
  }
}

async function refusalOf(call: Promise<unknown>, type: new () => Error): Promise<Error> {
  try {
    await call;
  } catch (error) {
    if (error instanceof type) return error;

    throw error;
  }

  throw new Error('expected the call to be refused');
}

function createFollowService(): { service: AthleteFollowService; follows: InMemoryFollows } {
  const follows = new InMemoryFollows();

  return { service: new AthleteFollowService(follows), follows };
}

function createLikeService(): { service: PhotoLikeService; likes: InMemoryLikes } {
  const likes = new InMemoryLikes();

  return { service: new PhotoLikeService(likes), likes };
}

describe('AthleteFollowService', () => {
  it('follows a visible profile once, however many times it is asked', async () => {
    const { service, follows } = createFollowService();

    follows.addProfile(PROFILE_ID, OTHER_USER_ID);

    await service.follow(viewer, PROFILE_ID);
    await expect(service.follow(viewer, PROFILE_ID)).resolves.toBeUndefined();

    expect(await follows.countFollowers(PROFILE_ID)).toBe(1);
  });

  it('unfollows idempotently', async () => {
    const { service, follows } = createFollowService();

    follows.addProfile(PROFILE_ID, OTHER_USER_ID);
    await service.follow(viewer, PROFILE_ID);

    await service.unfollow(viewer, PROFILE_ID);
    await expect(service.unfollow(viewer, PROFILE_ID)).resolves.toBeUndefined();

    expect(await follows.countFollowers(PROFILE_ID)).toBe(0);
  });

  it('refuses following the profile of the caller with the generic 404', async () => {
    const { service, follows } = createFollowService();

    follows.addProfile(PROFILE_ID, VIEWER_ID);

    const refused = await refusalOf(service.follow(viewer, PROFILE_ID), NotFoundException);

    expect(refused.message).toBe('Not Found');
    expect(await follows.countFollowers(PROFILE_ID)).toBe(0);
  });

  it('hides a missing and a non-visible profile behind the same 404', async () => {
    const { service, follows } = createFollowService();

    follows.addProfile(PROFILE_ID, OTHER_USER_ID, false);

    for (const profileId of [PROFILE_ID, OTHER_PROFILE_ID]) {
      const refused = await refusalOf(service.follow(viewer, profileId), NotFoundException);

      expect(refused.message).toBe('Not Found');
    }

    expect(await follows.countFollowers(PROFILE_ID)).toBe(0);
  });

  it('answers a count and one boolean, never who follows', async () => {
    const { service, follows } = createFollowService();

    follows.addProfile(PROFILE_ID, THIRD_USER_ID);
    await service.follow(viewer, PROFILE_ID);
    await service.follow(otherUser, PROFILE_ID);

    const seen: AthleteSocialView = await service.social(viewer, PROFILE_ID);

    expect(seen).toEqual({ followerCount: 2, viewerFollows: true });
    expect(Object.keys(seen).sort()).toEqual(['followerCount', 'viewerFollows']);
    expect(JSON.stringify(seen)).not.toContain(VIEWER_ID);
    expect(JSON.stringify(seen)).not.toContain(OTHER_USER_ID);

    await expect(service.social(thirdUser, PROFILE_ID)).resolves.toEqual({
      followerCount: 2,
      viewerFollows: false,
    });
  });
});

describe('PhotoLikeService', () => {
  it('likes an approved photo once, however many times it is asked', async () => {
    const { service, likes } = createLikeService();

    likes.addPhoto(PHOTO_ID, 'APPROVED');

    await service.like(viewer, PHOTO_ID);
    await expect(service.like(viewer, PHOTO_ID)).resolves.toBeUndefined();

    expect(await likes.count(PHOTO_ID)).toBe(1);
  });

  it('unlikes idempotently', async () => {
    const { service, likes } = createLikeService();

    likes.addPhoto(PHOTO_ID, 'APPROVED');
    await service.like(viewer, PHOTO_ID);

    await service.unlike(viewer, PHOTO_ID);
    await expect(service.unlike(viewer, PHOTO_ID)).resolves.toBeUndefined();

    expect(await likes.count(PHOTO_ID)).toBe(0);
  });

  it('refuses to like the photo of the caller with the generic 404', async () => {
    const { service, likes } = createLikeService();

    likes.addPhoto(PHOTO_ID, 'APPROVED', VIEWER_ID);

    const refused = await refusalOf(service.like(viewer, PHOTO_ID), NotFoundException);

    expect(refused.message).toBe('Not Found');
    expect(await likes.count(PHOTO_ID)).toBe(0);
  });

  it('refuses every non-APPROVED status and a missing photo with the same 404', async () => {
    const { service, likes } = createLikeService();

    const statuses: ProfilePhotoStatus[] = ['PENDING', 'REJECTED', 'REMOVED'];

    for (const [index, status] of statuses.entries()) {
      const photoId = `a0000000-0000-4000-8000-${String(index).padStart(12, '0')}`;

      likes.addPhoto(photoId, status);

      const refused = await refusalOf(service.like(viewer, photoId), NotFoundException);

      expect(refused.message).toBe('Not Found');
      expect(await likes.count(photoId)).toBe(0);
    }

    const missing = await refusalOf(service.like(viewer, OTHER_PROFILE_ID), NotFoundException);

    expect(missing.message).toBe('Not Found');
  });

  it('stops a fresh like the moment the photo is taken down, and keeps the count', async () => {
    const { service, likes } = createLikeService();

    likes.addPhoto(PHOTO_ID, 'APPROVED', THIRD_USER_ID);
    await service.like(viewer, PHOTO_ID);

    likes.addPhoto(PHOTO_ID, 'REMOVED');

    const refused = await refusalOf(service.like(otherUser, PHOTO_ID), NotFoundException);

    expect(refused.message).toBe('Not Found');
    expect(await likes.count(PHOTO_ID)).toBe(1);
  });

  it('answers a bare like count', async () => {
    const { service, likes } = createLikeService();

    likes.addPhoto(PHOTO_ID, 'APPROVED', THIRD_USER_ID);
    await service.like(viewer, PHOTO_ID);
    await service.like(otherUser, PHOTO_ID);

    const counted = await service.count(PHOTO_ID);

    expect(counted).toEqual({ likeCount: 2 });
    expect(JSON.stringify(counted)).not.toContain(VIEWER_ID);
    expect(JSON.stringify(counted)).not.toContain(OTHER_USER_ID);
  });
});

const REFUSAL = { statusCode: 429, message: 'Too Many Requests', requestId: REQUEST_ID };

function createLikeController(): {
  controller: PhotoLikeController;
  likes: InMemoryLikes;
  rateLimit: WindowRateLimit;
} {
  const likes = new InMemoryLikes();
  const rateLimit = new WindowRateLimit();

  likes.addPhoto(PHOTO_ID, 'APPROVED');

  return {
    controller: new PhotoLikeController(
      new PhotoLikeService(likes),
      rateLimit as unknown as RateLimitService,
    ),
    likes,
    rateLimit,
  };
}

function createFollowController(): {
  controller: AthleteFollowController;
  follows: InMemoryFollows;
  rateLimit: WindowRateLimit;
} {
  const follows = new InMemoryFollows();
  const rateLimit = new WindowRateLimit();

  follows.addProfile(PROFILE_ID, OTHER_USER_ID);

  return {
    controller: new AthleteFollowController(
      new AthleteFollowService(follows),
      rateLimit as unknown as RateLimitService,
    ),
    follows,
    rateLimit,
  };
}

function createRequest(userId = VIEWER_ID): AuthenticatedRequest {
  return {
    auth: { userId, role: Role.USER },
    id: REQUEST_ID,
    ip: IP,
  } as unknown as AuthenticatedRequest;
}

async function callLike(
  controller: PhotoLikeController,
  photoId = PHOTO_ID,
  userId = VIEWER_ID,
): Promise<{ response: RecordingResponse; body: unknown }> {
  const response = new RecordingResponse();
  const body = await controller.like(
    photoId,
    createRequest(userId),
    response as unknown as Response,
  );

  return { response, body };
}

async function callFollow(
  controller: AthleteFollowController,
  profileId = PROFILE_ID,
  userId = VIEWER_ID,
): Promise<{ response: RecordingResponse; body: unknown }> {
  const response = new RecordingResponse();
  const body = await controller.follow(
    profileId,
    createRequest(userId),
    response as unknown as Response,
  );

  return { response, body };
}

async function callUnfollow(
  controller: AthleteFollowController,
  profileId = PROFILE_ID,
  userId = VIEWER_ID,
): Promise<{ response: RecordingResponse; body: unknown }> {
  const response = new RecordingResponse();
  const body = await controller.unfollow(
    profileId,
    createRequest(userId),
    response as unknown as Response,
  );

  return { response, body };
}

describe('the social HTTP surface', () => {
  it('answers 204 on follow and unfollow, and a viewer-aware count between them', async () => {
    const { controller } = createFollowController();

    const follow = await callFollow(controller);

    expect(follow.body).toBeUndefined();

    await expect(controller.social(PROFILE_ID, createRequest())).resolves.toEqual({
      followerCount: 1,
      viewerFollows: true,
    });

    const unfollow = await callUnfollow(controller);

    expect(unfollow.body).toBeUndefined();
    expect(await controller.social(PROFILE_ID, createRequest(THIRD_USER_ID))).toEqual({
      followerCount: 0,
      viewerFollows: false,
    });
  });

  it('spends both budgets per call, the user windows first', async () => {
    const { controller, rateLimit } = createFollowController();

    await callFollow(controller);

    expect(rateLimit.calls).toHaveLength(6);
    expect(rateLimit.calls[0]).toEqual({
      scope: FOLLOW_RATE_LIMIT_SCOPES.user,
      identifier: VIEWER_ID,
      limit: FOLLOW_LIMITS.user[0].limit,
      windowSeconds: FOLLOW_LIMITS.user[0].windowSeconds,
    });
    expect(rateLimit.calls[3]).toMatchObject({
      scope: FOLLOW_RATE_LIMIT_SCOPES.address,
      identifier: IP,
    });
  });

  it('refuses with the shared envelope and Retry-After when the user window is full', async () => {
    const { controller, follows, rateLimit } = createFollowController();

    rateLimit.seed(FOLLOW_RATE_LIMIT_SCOPES.user, VIEWER_ID, 60, FOLLOW_LIMITS.user[0].limit);

    const refusal = await callFollow(controller);

    expect(refusal.body).toEqual(REFUSAL);
    expect(refusal.response.headers.get('retry-after')).toBe('60');
    expect(await follows.countFollowers(PROFILE_ID)).toBe(0);
  });

  it('charges unfollow against the same budget as follow', async () => {
    const { controller, follows, rateLimit } = createFollowController();

    await callFollow(controller);
    rateLimit.seed(FOLLOW_RATE_LIMIT_SCOPES.user, VIEWER_ID, 60, FOLLOW_LIMITS.user[0].limit + 1);

    const refusal = await callUnfollow(controller);

    expect(refusal.body).toEqual(REFUSAL);
    expect(await follows.countFollowers(PROFILE_ID)).toBe(1);
  });

  it('still holds an address budget across many different users', async () => {
    const { controller, follows, rateLimit } = createFollowController();

    let allowed = 0;
    let refusal: unknown;

    for (let index = 0; index < 25; index += 1) {
      const profileId = `b0000000-0000-4000-8000-${String(index).padStart(12, '0')}`;
      const userId = `c0000000-0000-4000-8000-${String(index).padStart(12, '0')}`;

      follows.addProfile(profileId, OTHER_USER_ID);

      const call = await callFollow(controller, profileId, userId);

      if (call.body === undefined) allowed += 1;
      else refusal = call.body;
    }

    expect(allowed).toBe(FOLLOW_LIMITS.address[0].limit);
    expect(refusal).toEqual(REFUSAL);
    expect(rateLimit.calls.some(({ scope }) => scope === FOLLOW_RATE_LIMIT_SCOPES.address)).toBe(
      true,
    );
  });

  it('cuts a 200-like burst from one account off at the per-user budget', async () => {
    const { controller, likes, rateLimit } = createLikeController();

    let allowed = 0;
    let last: { response: RecordingResponse; body: unknown } | undefined;

    for (let attempt = 0; attempt < 200; attempt += 1) {
      last = await callLike(controller);

      if (last.body === undefined) allowed += 1;
    }

    expect(allowed).toBe(PHOTO_LIKE_LIMITS.user[0].limit);
    expect(await likes.count(PHOTO_ID)).toBe(1);
    expect(last?.body).toEqual(REFUSAL);
    expect(last?.response.headers.get('retry-after')).toBe('60');
    expect(rateLimit.calls.at(-1)).toMatchObject({ scope: PHOTO_LIKE_RATE_LIMIT_SCOPES.user });
  });

  it('cuts 100 follows from one account off at the per-user budget', async () => {
    const { controller, follows, rateLimit } = createFollowController();

    let allowed = 0;
    let last: { response: RecordingResponse; body: unknown } | undefined;

    for (let attempt = 0; attempt < 100; attempt += 1) {
      last = await callFollow(controller);

      if (last.body === undefined) allowed += 1;
    }

    expect(allowed).toBe(FOLLOW_LIMITS.user[0].limit);
    expect(await follows.countFollowers(PROFILE_ID)).toBe(1);
    expect(last?.body).toEqual(REFUSAL);
    expect(rateLimit.calls.at(-1)).toMatchObject({ scope: FOLLOW_RATE_LIMIT_SCOPES.user });
  });

  it('answers a malformed id with the generic 400 before any counter is charged', async () => {
    const { controller, rateLimit } = createLikeController();

    await expect(callLike(controller, 'not-a-uuid')).rejects.toBeInstanceOf(BadRequestException);

    expect(rateLimit.calls).toEqual([]);
  });

  it('counts likes for anyone, per address only', async () => {
    const { controller, rateLimit } = createLikeController();

    const counted = await controller.count(
      PHOTO_ID,
      createRequest(),
      new RecordingResponse() as unknown as Response,
    );

    expect(counted).toEqual({ likeCount: 0 });
    expect(
      rateLimit.calls.map(({ scope, identifier, limit, windowSeconds }) => ({
        scope,
        identifier,
        limit,
        windowSeconds,
      })),
    ).toEqual(
      PHOTO_LIKE_COUNT_LIMITS.map((window) => ({
        scope: PHOTO_LIKE_COUNT_RATE_LIMIT_SCOPE,
        identifier: IP,
        ...window,
      })),
    );
  });

  it('marks exactly the non-public handlers @Authenticated', () => {
    for (const handler of [
      AthleteFollowController.prototype.social,
      AthleteFollowController.prototype.follow,
      AthleteFollowController.prototype.unfollow,
      PhotoLikeController.prototype.like,
      PhotoLikeController.prototype.unlike,
    ]) {
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBeUndefined();
    }

    expect(
      Reflect.getMetadata(AUTHENTICATED_KEY, PhotoLikeController.prototype.count),
    ).toBeUndefined();
    expect(Reflect.getMetadata(IS_PUBLIC_KEY, PhotoLikeController.prototype.count)).toBe(true);
  });

  it('exposes the agreed routes on the agreed paths', () => {
    expect(Reflect.getMetadata(PATH_METADATA, AthleteFollowController)).toBe('athletes');
    expect(Reflect.getMetadata(PATH_METADATA, PhotoLikeController)).toBe('photos');

    const routes: [string, object, number, string][] = [
      ['social', AthleteFollowController.prototype.social, RequestMethod.GET, ':profileId/social'],
      ['follow', AthleteFollowController.prototype.follow, RequestMethod.PUT, ':profileId/follow'],
      [
        'unfollow',
        AthleteFollowController.prototype.unfollow,
        RequestMethod.DELETE,
        ':profileId/follow',
      ],
      ['like', PhotoLikeController.prototype.like, RequestMethod.PUT, ':photoId/like'],
      ['unlike', PhotoLikeController.prototype.unlike, RequestMethod.DELETE, ':photoId/like'],
      ['count', PhotoLikeController.prototype.count, RequestMethod.GET, ':photoId/likes/count'],
    ];

    for (const [, handler, method, path] of routes) {
      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(method);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(path);
    }
  });
});
