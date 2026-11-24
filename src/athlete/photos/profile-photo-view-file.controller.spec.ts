import {
  InternalServerErrorException,
  NotFoundException,
  RequestMethod,
  ServiceUnavailableException,
} from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Request, Response } from 'express';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../../auth/decorators/roles.decorator';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';
import { ProfilePhotoViewFileController } from './profile-photo-view-file.controller';
import {
  PROFILE_PHOTO_VIEW_FILE_LIMITS,
  PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE,
} from './profile-photo-view-limits';
import type { ProfilePhotoBytes, ProfilePhotoViewService } from './profile-photo-view.service';

/**
 * `GET /photos/view/:token`, driven directly: the controller and the shared
 * limiter are the real ones, the view service is a stand-in that answers with
 * the bytes `redeem()` produced or throws what it throws.
 *
 * What this spec pins is the shape of the answer: the exact header set every
 * response carries, that the body is the record's bytes and never a partial
 * write, that a refused attempt costs no redemption, and that the route is
 * public with no other marker on it - the token is the whole credential.
 */

const TOKEN = 'eyJwYXlsb2FkIjoiYSJ9.signature';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';
const BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** The response surface the controller uses, recording what it was told. */
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

  /** The whole photo arrives in one call; nothing here streams. */
  end(chunk?: unknown): this {
    this.body = chunk;
    this.headersSent = true;
    return this;
  }
}

/** A request with as much as this route reads: an id to echo, an address to count. */
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

/** The one call the controller makes, with a settable answer or failure. */
class FakeViews {
  readonly tokens: string[] = [];
  result: ProfilePhotoBytes = {
    bytes: BYTES,
    contentType: 'image/png',
    sizeBytes: BYTES.length,
  };
  failure: unknown = null;

  async redeem(token: string): Promise<ProfilePhotoBytes> {
    this.tokens.push(token);

    if (this.failure !== null) throw this.failure;

    return this.result;
  }
}

/**
 * Same fixed-window semantics as the Redis limiter, one counter per window.
 *
 * The two windows must stay apart: this spec needs to show that the hourly
 * budget refuses even when the minute still has room.
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
  seed(identifier: string, windowSeconds: number, hits: number): void {
    this.counters.set(
      `${PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE}:${identifier}:${windowSeconds}`,
      hits,
    );
  }
}

function createController() {
  const views = new FakeViews();
  const rateLimit = new WindowRateLimit();

  const controller = new ProfilePhotoViewFileController(
    views as unknown as ProfilePhotoViewService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, views, rateLimit };
}

/** Runs the handler once against a fresh response, returning it and any failure. */
async function call(
  controller: ProfilePhotoViewFileController,
  request: Request = createRequest(),
): Promise<{ response: RecordingResponse; error: unknown }> {
  const response = new RecordingResponse();

  try {
    await controller.view(TOKEN, request, response as unknown as Response);
  } catch (error) {
    return { response, error };
  }

  return { response, error: null };
}

/** The exact set of headers a successful answer carries - nothing more. */
function successHeaders(contentLength: number): Map<string, string> {
  return new Map<string, string>([
    ['cache-control', 'no-store'],
    ['pragma', 'no-cache'],
    ['x-content-type-options', 'nosniff'],
    ['content-disposition', 'inline'],
    ['referrer-policy', 'no-referrer'],
    ['content-security-policy', "default-src 'none'; sandbox"],
    ['cross-origin-resource-policy', 'same-site'],
    ['content-type', 'image/png'],
    ['content-length', String(contentLength)],
  ]);
}

describe('ProfilePhotoViewFileController', () => {
  describe('the photo', () => {
    it('serves the decrypted bytes with the headers that keep the link private', async () => {
      const { controller, views } = createController();

      const { response, error } = await call(controller);

      expect(error).toBeNull();
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe(BYTES);
      expect(response.headers).toEqual(successHeaders(BYTES.length));
      // Redeemed exactly once, with the token from the path, unchanged.
      expect(views.tokens).toEqual([TOKEN]);
    });

    it('takes the media type from the record, not from the caller', async () => {
      const { controller, views } = createController();

      views.result = { bytes: BYTES, contentType: 'image/jpeg', sizeBytes: BYTES.length };

      const { response } = await call(
        controller,
        createRequest({ headers: { accept: 'text/html' } }),
      );

      expect(response.headers.get('content-type')).toBe('image/jpeg');
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('sends no bytes when the record names a type it must not serve', async () => {
      const { controller, views } = createController();

      views.result = {
        bytes: BYTES,
        // A stored row is still checked: anything outside the two formats is
        // treated as corruption, not as something to echo.
        contentType: 'image/svg+xml' as unknown as ProfilePhotoBytes['contentType'],
        sizeBytes: BYTES.length,
      };

      const { response, error } = await call(controller);

      expect(error).toBeInstanceOf(InternalServerErrorException);
      expect(response.headersSent).toBe(false);
      expect(response.headers.has('content-type')).toBe(false);
    });

    it('passes a refusal from the service through untouched', async () => {
      const { controller, views } = createController();

      views.failure = new NotFoundException();

      const { response, error } = await call(controller);

      expect(error).toBeInstanceOf(NotFoundException);
      // Nothing of the photo left the process.
      expect(response.headersSent).toBe(false);
      expect(response.body).toBeUndefined();
    });

    it('answers 503, not 404, when the service cannot reach a dependency', async () => {
      const { controller, views } = createController();

      views.failure = new ServiceUnavailableException();

      const { response, error } = await call(controller);

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(response.headersSent).toBe(false);
    });
  });

  describe('the budget', () => {
    it('counts the address, in both windows, before the token is redeemed', async () => {
      const { controller, rateLimit } = createController();

      await call(controller);

      expect(rateLimit.calls).toEqual([
        {
          scope: PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_VIEW_FILE_LIMITS[0],
        },
        {
          scope: PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PROFILE_PHOTO_VIEW_FILE_LIMITS[1],
        },
      ]);
    });

    it('refuses the twenty-first request in a minute without redeeming it', async () => {
      const { controller, views, rateLimit } = createController();

      for (let attempt = 1; attempt <= 20; attempt += 1) {
        const { response } = await call(controller);

        expect(response.statusCode).toBe(200);
      }

      const { response } = await call(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      // The refused attempt never reached the service: no nonce spent, no bytes.
      expect(views.tokens).toHaveLength(20);
      expect(rateLimit.calls).toHaveLength(41);
    });

    it('refuses on the hourly window even when the minute has room', async () => {
      const { controller, views, rateLimit } = createController();

      rateLimit.seed(IP, 3_600, 100);

      const { response } = await call(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('3600');
      // Both windows were consulted, and the refused call never redeemed.
      expect(rateLimit.calls.map((entry) => entry.windowSeconds)).toEqual([60, 3_600]);
      expect(views.tokens).toEqual([]);
    });

    it('falls back to a fixed identifier when the address is unknown', async () => {
      const { controller, rateLimit } = createController();

      await call(controller, createRequest({ ip: undefined, socket: {} }));

      expect(rateLimit.calls[0]?.identifier).toBe('unknown');
    });
  });

  describe('the route', () => {
    it('is a public GET on photos/view/:token', () => {
      const handler = ProfilePhotoViewFileController.prototype.view;

      expect(Reflect.getMetadata(PATH_METADATA, ProfilePhotoViewFileController)).toBe(
        'photos/view',
      );
      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(':token');
    });

    it('carries the public marker and no other, because the token is the credential', () => {
      const handler = ProfilePhotoViewFileController.prototype.view;

      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      // A role, a step-up or an identity check here would break the `<img>` that
      // follows the link, and would disagree with the basis already in the token.
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(REQUIRES_IDENTITY_VERIFIER_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
    });
  });
});
