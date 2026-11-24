import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
  RequestMethod,
} from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Request, Response } from 'express';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { ROLES_KEY } from '../../auth/decorators/roles.decorator';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';
import { PublicProfilePhotosController } from './public-profile-photos.controller';
import {
  PROFILE_PHOTO_PUBLIC_FILE_LIMITS,
  PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE,
  PROFILE_PHOTO_PUBLIC_LIST_LIMITS,
  PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE,
} from './profile-photo-view-limits';
import type {
  ApprovedPhotoPage,
  ProfilePhotoBytes,
  ProfilePhotoViewService,
} from './profile-photo-view.service';

/**
 * The two unauthenticated photo routes, driven directly.
 *
 * The controller and the shared limiter are the real ones; the view service is a
 * stand-in. What this spec pins is the surface a stranger sees: the exact
 * headers on the bytes route, the metadata-only page on the listing route, that
 * a malformed id or query is the generic 400 before any work happens, that a
 * refused attempt never reaches the service, and that neither route carries a
 * role or a step-up marker.
 */

const PHOTO_ID = '3f0a2c1e-8b3d-4f5a-9c7e-1d2b3a4c5d6e';
const PROFILE_ID = '9b1c2d3e-4f5a-4b6c-8d7e-0a1b2c3d4e5f';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';
const BYTES = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);

/** The response surface these controllers use, recording what it was told. */
class RecordingResponse {
  readonly headers = new Map<string, string>();
  statusCode = 200;
  body: unknown = undefined;
  headersSent = false;

  setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  json(payload: unknown): this {
    this.body = payload;
    this.headersSent = true;
    return this;
  }

  end(chunk?: unknown): this {
    this.body = chunk;
    this.headersSent = true;
    return this;
  }
}

/** A request with as much as these routes read: an id to echo, an address to count. */
function createRequest(overrides: Record<string, unknown> = {}): Request {
  return {
    id: REQUEST_ID,
    method: 'GET',
    ip: IP,
    headers: {},
    socket: { remoteAddress: IP },
    ...overrides,
  } as unknown as Request;
}

/** Both calls the controller may make, with settable answers. */
class FakeViews {
  readonly reads: string[] = [];
  readonly lists: { profileId: string; limit: number; cursor?: string }[] = [];
  result: ProfilePhotoBytes = {
    bytes: BYTES,
    contentType: 'image/png',
    sizeBytes: BYTES.length,
  };
  page: ApprovedPhotoPage = { photos: [], nextCursor: null };
  failure: unknown = null;

  async readApproved(photoId: string): Promise<ProfilePhotoBytes> {
    this.reads.push(photoId);

    if (this.failure !== null) throw this.failure;

    return this.result;
  }

  async listApproved(
    profileId: string,
    request: { limit: number; cursor?: string },
  ): Promise<ApprovedPhotoPage> {
    this.lists.push({ profileId, ...request });

    if (this.failure !== null) throw this.failure;

    return this.page;
  }
}

/**
 * Same fixed-window semantics as the Redis limiter, one counter per scope and
 * window: the two surfaces here have separate budgets and must not share one.
 */
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

  /** Fills one window, so a test can arrive with the budget already spent. */
  seed(scope: string, identifier: string, windowSeconds: number, hits: number): void {
    this.counters.set(`${scope}:${identifier}:${windowSeconds}`, hits);
  }
}

function createController() {
  const views = new FakeViews();
  const rateLimit = new WindowRateLimit();

  const controller = new PublicProfilePhotosController(
    views as unknown as ProfilePhotoViewService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, views, rateLimit };
}

/** Runs the bytes handler once against a fresh response. */
async function callRead(
  controller: PublicProfilePhotosController,
  photoId: string = PHOTO_ID,
  request: Request = createRequest(),
): Promise<{ response: RecordingResponse; error: unknown }> {
  const response = new RecordingResponse();

  try {
    await controller.read(photoId, request, response as unknown as Response);
  } catch (error) {
    return { response, error };
  }

  return { response, error: null };
}

/** Runs the listing handler once; the body is what the handler returns. */
async function callList(
  controller: PublicProfilePhotosController,
  options: { profileId?: string; query?: unknown; request?: Request } = {},
): Promise<{ response: RecordingResponse; body: unknown; error: unknown }> {
  const response = new RecordingResponse();

  try {
    const body = await controller.list(
      options.profileId ?? PROFILE_ID,
      options.query ?? {},
      options.request ?? createRequest(),
      response as unknown as Response,
    );

    return { response, body, error: null };
  } catch (error) {
    return { response, body: undefined, error };
  }
}

describe('PublicProfilePhotosController', () => {
  describe('the bytes route', () => {
    it('serves the decrypted bytes with the public-cache-proof headers', async () => {
      const { controller, views } = createController();

      const { response, error } = await callRead(controller);

      expect(error).toBeNull();
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe(BYTES);
      expect(response.headers).toEqual(
        new Map<string, string>([
          ['cache-control', 'no-store'],
          ['pragma', 'no-cache'],
          ['x-content-type-options', 'nosniff'],
          ['content-disposition', 'inline'],
          ['referrer-policy', 'no-referrer'],
          ['content-security-policy', "default-src 'none'; sandbox"],
          // Public on purpose, and the app lives on another origin.
          ['cross-origin-resource-policy', 'cross-origin'],
          ['content-type', 'image/png'],
          ['content-length', String(BYTES.length)],
        ]),
      );
      expect(views.reads).toEqual([PHOTO_ID]);
    });

    it('answers a malformed id with the generic 400 and reads nothing', async () => {
      const { controller, views } = createController();

      const { response, error } = await callRead(controller, 'not-a-uuid');

      expect(error).toBeInstanceOf(BadRequestException);
      expect(views.reads).toEqual([]);
      expect(response.headersSent).toBe(false);
    });

    it('serves only the two types ingest writes, and never echoes another', async () => {
      const { controller, views } = createController();

      views.result = {
        bytes: BYTES,
        contentType: 'image/svg+xml' as unknown as ProfilePhotoBytes['contentType'],
        sizeBytes: BYTES.length,
      };

      const { response, error } = await callRead(controller);

      expect(error).toBeInstanceOf(InternalServerErrorException);
      expect(response.headersSent).toBe(false);
      expect(response.headers.has('content-type')).toBe(false);
    });

    it('passes the service refusal through, with no bytes and no extra headers', async () => {
      const { controller, views } = createController();

      views.failure = new NotFoundException();

      const { response, error } = await callRead(controller);

      expect(error).toBeInstanceOf(NotFoundException);
      expect(response.headersSent).toBe(false);
      // The hardening headers are still set: a refusal and a success differ only
      // in the status and the body.
      expect(response.headers.get('cache-control')).toBe('no-store');
    });
  });

  describe('the listing route', () => {
    it('returns the page as it came, marked uncacheable', async () => {
      const { controller, views } = createController();
      const page: ApprovedPhotoPage = {
        photos: [
          {
            id: PHOTO_ID,
            caption: 'finish line',
            contentType: 'image/png',
            sizeBytes: BYTES.length,
            createdAt: new Date(0).toISOString(),
          },
        ],
        nextCursor: PHOTO_ID,
      };

      views.page = page;

      const { response, body, error } = await callList(controller);

      expect(error).toBeNull();
      expect(body).toBe(page);
      expect(response.headers.get('cache-control')).toBe('no-store');
      // The default page is the schema's, not something the caller chose.
      expect(views.lists).toEqual([{ profileId: PROFILE_ID, limit: 20 }]);
    });

    it('passes the caller page size and cursor through as numbers and a string', async () => {
      const { controller, views } = createController();

      await callList(controller, { query: { limit: '7', cursor: PHOTO_ID } });

      expect(views.lists).toEqual([{ profileId: PROFILE_ID, limit: 7, cursor: PHOTO_ID }]);
    });

    it('answers the generic 400 for a query key the schema does not know', async () => {
      const { controller, views, rateLimit } = createController();

      const { error } = await callList(controller, { query: { limit: '7', offset: '3' } });

      expect(error).toBeInstanceOf(BadRequestException);
      // Rejected before any budget is spent or any row read.
      expect(rateLimit.calls).toEqual([]);
      expect(views.lists).toEqual([]);
    });

    it('caps the page size at the schema maximum', async () => {
      const { controller, views } = createController();

      const tooBig = await callList(controller, { query: { limit: '51' } });
      const zero = await callList(controller, { query: { limit: '0' } });

      expect(tooBig.error).toBeInstanceOf(BadRequestException);
      expect(zero.error).toBeInstanceOf(BadRequestException);
      expect(views.lists).toEqual([]);
    });

    it('answers the generic 400 for a malformed profile id without listing', async () => {
      const { controller, views } = createController();

      const { error } = await callList(controller, { profileId: 'not-a-uuid' });

      expect(error).toBeInstanceOf(BadRequestException);
      expect(views.lists).toEqual([]);
    });

    it('passes a service refusal through untouched', async () => {
      const { controller, views } = createController();

      views.failure = new NotFoundException();

      const { body, error } = await callList(controller);

      expect(error).toBeInstanceOf(NotFoundException);
      expect(body).toBeUndefined();
    });
  });

  describe('the budget', () => {
    it('counts both windows of both surfaces per address, before any work', async () => {
      const { controller, rateLimit } = createController();

      await callRead(controller);
      await callList(controller);

      expect(rateLimit.calls).toEqual([
        {
          scope: PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_PUBLIC_FILE_LIMITS[0],
        },
        {
          scope: PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_PUBLIC_FILE_LIMITS[1],
        },
        {
          scope: PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_PUBLIC_LIST_LIMITS[0],
        },
        {
          scope: PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_PUBLIC_LIST_LIMITS[1],
        },
      ]);
    });

    it('refuses the 121st photo in a minute without reading it', async () => {
      const { controller, views, rateLimit } = createController();

      for (let attempt = 1; attempt <= 120; attempt += 1) {
        const { response } = await callRead(controller);

        expect(response.statusCode).toBe(200);
      }

      const { response } = await callRead(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(views.reads).toHaveLength(120);
      expect(rateLimit.calls).toHaveLength(241);
    });

    it('refuses the 61st listing in a minute with the same envelope, before listing', async () => {
      const { controller, views, rateLimit } = createController();

      rateLimit.seed(PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE, IP, 60, 60);

      const { response, body } = await callList(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(views.lists).toEqual([]);
      // The hourly window was never consulted: the first refusal wins.
      expect(rateLimit.calls.map((entry) => entry.windowSeconds)).toEqual([60]);
    });

    it('keeps the two surfaces on separate budgets', async () => {
      const { controller, views, rateLimit } = createController();

      // The bytes budget is spent, the listing one is untouched.
      rateLimit.seed(PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE, IP, 60, 120);

      const refusedRead = await callRead(controller);
      const servedList = await callList(controller);

      expect(refusedRead.response.statusCode).toBe(429);
      expect(views.reads).toEqual([]);
      expect(servedList.error).toBeNull();
      expect(views.lists).toHaveLength(1);
    });

    it('falls back to a fixed identifier when the address is unknown', async () => {
      const { controller, rateLimit } = createController();

      await callRead(controller, PHOTO_ID, createRequest({ ip: undefined, socket: {} }));

      expect(rateLimit.calls[0]?.identifier).toBe('unknown');
    });
  });

  describe('the routes', () => {
    it('mounts both handlers under public/', () => {
      expect(Reflect.getMetadata(PATH_METADATA, PublicProfilePhotosController)).toBe('public');
    });

    it('exposes the bytes route as a public GET photos/:photoId', () => {
      const handler = PublicProfilePhotosController.prototype.read;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe('photos/:photoId');
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      // No identity is asked for: anyone may read an approved photo.
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
    });

    it('exposes the listing route as a public GET athlete-profiles/:athleteProfileId/photos', () => {
      const handler = PublicProfilePhotosController.prototype.list;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(
        'athlete-profiles/:athleteProfileId/photos',
      );
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
    });
  });
});
