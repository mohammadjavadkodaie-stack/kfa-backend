import { BadRequestException, RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Request, Response } from 'express';
import { AUTHENTICATED_KEY } from '../auth/decorators/authenticated.decorator';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import type { RateLimitService } from '../rate-limit/rate-limit.service';
import { PublicCompanyController } from './public-company.controller';
import type { PublicCompanyQuery } from './public-company.dto';
import {
  PUBLIC_COMPANY_LIST_LIMITS,
  PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE,
  PUBLIC_COMPANY_READ_LIMITS,
  PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE,
} from './public-company-limits';
import type {
  PublicCompanyItem,
  PublicCompanyPage,
  PublicCompanyService,
} from './public-company.service';

/**
 * The two unauthenticated company routes, driven directly.
 *
 * The controller and the shared limiter are the real ones; the service is a
 * stand-in. Pinned here: strict parsing before any counter, the per-address
 * budget and its shared 429 envelope, the short public cache headers set only
 * after the limiter passed, the explicit `@Public()` marker and the absence of
 * every identity marker.
 */

const SLUG = 'acme-rockets';
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

class FakePublicCompanyService {
  readonly lists: PublicCompanyQuery[] = [];
  readonly reads: string[] = [];
  page: PublicCompanyPage = { items: [], nextCursor: null };
  item: PublicCompanyItem = {
    slug: SLUG,
    displayName: 'Acme Rockets',
    country: 'TR',
    kind: 'SPONSOR',
    description: null,
    websiteUrl: null,
  };
  failure: unknown = null;

  async list(query: PublicCompanyQuery): Promise<PublicCompanyPage> {
    this.lists.push(query);

    if (this.failure !== null) throw this.failure;

    return this.page;
  }

  async read(slug: string): Promise<PublicCompanyItem> {
    this.reads.push(slug);

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
  const companies = new FakePublicCompanyService();
  const rateLimit = new WindowRateLimit();
  const controller = new PublicCompanyController(
    companies as unknown as PublicCompanyService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, companies, rateLimit };
}

async function callList(
  controller: PublicCompanyController,
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
  controller: PublicCompanyController,
  slug: string = SLUG,
  request: Request = createRequest(),
): Promise<{ response: RecordingResponse; body: unknown; error: unknown }> {
  const response = new RecordingResponse();

  try {
    const body = await controller.read(slug, request, response as unknown as Response);

    return { response, body, error: null };
  } catch (error) {
    return { response, body: undefined, error };
  }
}

describe('PublicCompanyController', () => {
  describe('the list route', () => {
    it('serves a page with the short public cache headers', async () => {
      const { controller, companies } = createController();

      companies.page = { items: [companies.item], nextCursor: SLUG };

      const { response, body, error } = await callList(controller);

      expect(error).toBeNull();
      expect(body).toEqual(companies.page);
      expect(response.headers.get('cache-control')).toBe('public, max-age=30');
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('defaults the page size and passes the parsed cursor and kind through', async () => {
      const { controller, companies } = createController();

      await callList(controller);
      await callList(controller, { limit: '7', cursor: SLUG, kind: 'SPONSOR' });

      expect(companies.lists).toEqual([{ limit: 20 }, { limit: 7, cursor: SLUG, kind: 'SPONSOR' }]);
    });

    it('answers the generic 400 for every bad query, before any counter', async () => {
      const { controller, companies, rateLimit } = createController();

      const attempts = await Promise.all([
        callList(controller, { limit: '7', offset: '3' }),
        callList(controller, { limit: '0' }),
        callList(controller, { limit: '51' }),
        callList(controller, { kind: 'BOGUS' }),
        callList(controller, { cursor: 'Not A Slug' }),
      ]);

      for (const attempt of attempts) {
        expect(attempt.error).toBeInstanceOf(BadRequestException);
      }

      expect(rateLimit.calls).toEqual([]);
      expect(companies.lists).toEqual([]);
    });

    it('refuses the 61st page in a minute with the shared envelope, before listing', async () => {
      const { controller, companies, rateLimit } = createController();

      rateLimit.seed(PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE, IP, 60, 60);

      const { response, body } = await callList(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(companies.lists).toEqual([]);
      // A 429 must never be publicly cacheable.
      expect(response.headers.has('cache-control')).toBe(false);
      expect(response.headers.has('x-content-type-options')).toBe(false);
      // The hourly window was never consulted: the first refusal wins.
      expect(rateLimit.calls.map((entry) => entry.windowSeconds)).toEqual([60]);
    });
  });


  describe('the single-company route', () => {
    it('serves one card with the same headers', async () => {
      const { controller, companies } = createController();

      const { response, body, error } = await callRead(controller);

      expect(error).toBeNull();
      expect(body).toEqual(companies.item);
      expect(response.headers.get('cache-control')).toBe('public, max-age=30');
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    });

    it('leaves a malformed slug to the service, which answers the generic 404', async () => {
      const { controller, companies, rateLimit } = createController();

      const { error } = await callRead(controller, 'Not A Slug');

      // Not a 400: the route must not tell a malformed slug from a missing one.
      expect(error).toBeNull();
      expect(companies.reads).toEqual(['Not A Slug']);
      expect(rateLimit.calls).toHaveLength(2);
    });

    it('passes a service refusal through untouched', async () => {
      const { controller, companies } = createController();

      companies.failure = new BadRequestException('not used');

      const { body, error } = await callRead(controller);

      expect(error).toBeInstanceOf(BadRequestException);
      expect(body).toBeUndefined();
    });

    it('refuses the 121st read in a minute on its own budget', async () => {
      const { controller, companies, rateLimit } = createController();

      rateLimit.seed(PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE, IP, 60, 120);

      const { response, body } = await callRead(controller);

      expect(response.statusCode).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(companies.reads).toEqual([]);
      expect(response.headers.has('cache-control')).toBe(false);
    });
  });

  describe('the budget', () => {
    it('counts both windows per address, on separate scopes', async () => {
      const { controller, rateLimit } = createController();

      await callList(controller);
      await callRead(controller);

      expect(rateLimit.calls).toEqual([
        {
          scope: PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_COMPANY_LIST_LIMITS[0],
        },
        {
          scope: PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_COMPANY_LIST_LIMITS[1],
        },
        {
          scope: PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_COMPANY_READ_LIMITS[0],
        },
        {
          scope: PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...PUBLIC_COMPANY_READ_LIMITS[1],
        },
      ]);
    });

    it('falls back to a fixed identifier when the address is unknown', async () => {
      const { controller, rateLimit } = createController();

      await callRead(controller, SLUG, createRequest({ ip: undefined, socket: {} }));

      expect(rateLimit.calls[0]?.identifier).toBe('unknown');
    });
  });

  describe('the routes', () => {
    it('mounts both handlers under public/companies', () => {
      expect(Reflect.getMetadata(PATH_METADATA, PublicCompanyController)).toBe('public/companies');
    });

    it('exposes the page as an explicit public GET', () => {
      const handler = PublicCompanyController.prototype.list;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe('/');
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBeUndefined();
    });

    it('exposes the single read as an explicit public GET by slug', () => {
      const handler = PublicCompanyController.prototype.read;

      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(':slug');
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBeUndefined();
    });
  });
});

