import { BadRequestException, RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Request, Response } from 'express';
import { AUTHENTICATED_KEY } from '../auth/decorators/authenticated.decorator';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import type { RateLimitService } from '../rate-limit/rate-limit.service';
import { PublicRankingController } from './public-ranking.controller';
import type { PublicRankingQuery } from './public-ranking.dto';
import type {
  PublicRankingItem,
  PublicRankingPage,
  PublicRankingService,
} from './public-ranking.service';
import {
  PUBLIC_RANKING_LIST_LIMITS,
  PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE,
  PUBLIC_RANKING_READ_LIMITS,
  PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE,
} from './ranking-limits';

/**
 * The two unauthenticated leaderboard routes, driven directly.
 *
 * The controller and the shared limiter are the real ones; the service is a
 * stand-in. Pinned here: strict parsing before any counter, the per-address
 * budget and its shared 429 envelope, the short public cache headers, the
 * explicit `@Public()` marker and the absence of every identity marker.
 */

const PROFILE_ID = '9b1c2d3e-4f5a-4b6c-8d7e-0a1b2c3d4e5f';
const OTHER_PROFILE_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';

/** The response surface these handlers use, recording what it was told. */
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

class FakePublicRankingService {
  readonly lists: PublicRankingQuery[] = [];
  readonly reads: string[] = [];
  page: PublicRankingPage = { items: [], nextCursor: null };
  item: PublicRankingItem = { athleteProfileId: PROFILE_ID, totalPoints: 12, rank: 3 };
  failure: unknown = null;

  async list(query: PublicRankingQuery): Promise<PublicRankingPage> {
    this.lists.push(query);

    if (this.failure !== null) throw this.failure;

    return this.page;
  }

  async read(athleteProfileId: string): Promise<PublicRankingItem> {
    this.reads.push(athleteProfileId);

    if (this.failure !== null) throw this.failure;

    return this.item;
  }
}

/** Same fixed-window semantics as the Redis limiter, one counter per scope and window. */
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

function createController() {
  const ranking = new FakePublicRankingService();
  const rateLimit = new WindowRateLimit();
  const controller = new PublicRankingController(
    ranking as unknown as PublicRankingService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, ranking, rateLimit };
}

async function callList(
  controller: PublicRankingController,
  query: unknown = {},
  request: Request = createRequest(),
): Promise<{ response: RecordingResponse; body: unknown; error: unknown }> {
  const response = new RecordingResponse();

  try {
    const body = await controller.list(query, request, response as unknown as Response);

    return { response, body, error: null };
  } catch (error) {
    return { response, body: undefined, error };
  }
}

async function callRead(
  controller: PublicRankingController,
  athleteProfileId: string = PROFILE_ID,
  request: Request = createRequest(),
): Promise<{ response: RecordingResponse; body: unknown; error: unknown }> {
  const response = new RecordingResponse();

  try {
    const body = await controller.read(athleteProfileId, request, response as unknown as Response);

    return { response, body, error: null };
  } catch (error) {
    return { response, body: undefined, error };
  }
}

describe('PublicRankingController', () => {
  describe('the list route', () => {
    it('serves a page with the short public cache headers', async () => {
      const { controller, ranking } = createController();

      ranking.page = {
        items: [{ athleteProfileId: PROFILE_ID, totalPoints: 12, rank: 3 }],
        nextCursor: null,
      };

      const { response, body, error } = await callList(controller);

      expect(error).toBeNull();
      expect(body).toEqual(ranking.page);
      expect(response.headers.get('cache-control')).toBe('public, max-age=30');
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('defaults the page size and passes a parsed cursor through', async () => {
      const { controller, ranking } = createController();

      await callList(controller);
      await callList(controller, { limit: '7', cursor: OTHER_PROFILE_ID });

      expect(ranking.lists).toEqual([{ limit: 20 }, { limit: 7, cursor: OTHER_PROFILE_ID }]);
    });

    it('answers the generic 400 for an unknown query key, before any counter', async () => {
      const { controller, ranking, rateLimit } = createController();

      const { error } = await callList(controller, { limit: '7', offset: '3' });

      expect(error).toBeInstanceOf(BadRequestException);
      expect(rateLimit.calls).toEqual([]);
      expect(ranking.lists).toEqual([]);
    });

    it('caps the page size and refuses a malformed cursor with the same 400', async () => {
      const { controller, ranking, rateLimit } = createController();

      const tooBig = await callList(controller, { limit: '51' });
      const zero = await callList(controller, { limit: '0' });
      const badCursor = await callList(controller, { cursor: 'not-a-uuid' });

      for (const attempt of [tooBig, zero, badCursor]) {
        expect(attempt.error).toBeInstanceOf(BadRequestException);
      }

      expect(rateLimit.calls).toEqual([]);
      expect(ranking.lists).toEqual([]);
    });

    it('refuses the 61st page in a minute with the shared envelope, before listing', async () => {
      const { controller, ranking, rateLimit } = createController();

      rateLimit.seed(PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE, IP, 60, 60);

      const { response, body } = await callList(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(ranking.lists).toEqual([]);
      // The hourly window was never consulted: the first refusal wins.
      expect(rateLimit.calls.map((entry) => entry.windowSeconds)).toEqual([60]);
    });
  });

  describe('the single-athlete route', () => {
    it('serves one entry with the same headers', async () => {
      const { controller, ranking } = createController();

      const { response, body, error } = await callRead(controller);

      expect(error).toBeNull();
      expect(body).toEqual(ranking.item);
      expect(response.headers.get('cache-control')).toBe('public, max-age=30');
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('answers the generic 400 for a malformed id, before any counter', async () => {
      const { controller, ranking, rateLimit } = createController();

      const { error } = await callRead(controller, 'not-a-uuid');

      expect(error).toBeInstanceOf(BadRequestException);
      expect(rateLimit.calls).toEqual([]);
      expect(ranking.reads).toEqual([]);
    });

    it('passes a service refusal through untouched', async () => {
      const { controller, ranking } = createController();

      ranking.failure = new BadRequestException('not used');

      const { body, error } = await callRead(controller);

      expect(error).toBeInstanceOf(BadRequestException);
      expect(body).toBeUndefined();
    });

    it('refuses the 121st read in a minute on its own budget', async () => {
      const { controller, ranking, rateLimit } = createController();

      rateLimit.seed(PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE, IP, 60, 120);

      const { response, body } = await callRead(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(ranking.reads).toEqual([]);
    });
  });

  describe('the budget', () => {
    it('counts both windows per address, on separate scopes', async () => {
      const { controller, rateLimit } = createController();

      await callList(controller);
      await callRead(controller);

      expect(rateLimit.calls).toEqual([
        {
          scope: PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_RANKING_LIST_LIMITS[0],
        },
        {
          scope: PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_RANKING_LIST_LIMITS[1],
        },
        {
          scope: PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_RANKING_READ_LIMITS[0],
        },
        {
          scope: PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_RANKING_READ_LIMITS[1],
        },
      ]);
    });

    it('falls back to a fixed identifier when the address is unknown', async () => {
      const { controller, rateLimit } = createController();

      await callRead(controller, PROFILE_ID, createRequest({ ip: undefined, socket: {} }));

      expect(rateLimit.calls[0]?.identifier).toBe('unknown');
    });
  });

  describe('the routes', () => {
    it('mounts both handlers under public/ranking', () => {
      expect(Reflect.getMetadata(PATH_METADATA, PublicRankingController)).toBe('public/ranking');
    });

    it('exposes the page as an explicit public GET', () => {
      const handler = PublicRankingController.prototype.list;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe('/');
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBeUndefined();
    });

    it('exposes the single read as an explicit public GET by profile id', () => {
      const handler = PublicRankingController.prototype.read;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(':athleteProfileId');
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBeUndefined();
    });
  });
});
