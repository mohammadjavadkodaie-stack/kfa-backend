import {
  InternalServerErrorException,
  RequestMethod,
  ServiceUnavailableException,
} from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import type { Request, Response } from 'express';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../../auth/decorators/roles.decorator';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';
import type { DocumentContentType } from '../records/identity-document.repository';
import { DocumentViewFileController } from './document-view-file.controller';
import type { DocumentViewBytes, DocumentViewService } from './document-view.service';
import { DOCUMENT_VIEW_FILE_LIMITS, DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE } from './view-link-limits';

/**
 * `GET /documents/view/:token`, driven directly: the controller and the limiter
 * are the real ones, the view service is a stand-in that answers with the bytes
 * or throws - exactly what `redeem()` does after its own checks.
 *
 * What this spec pins is the shape of the answer: which headers every response
 * carries, that the body is the record's bytes and never a partial write, that
 * a refused attempt costs no redemption, and that the route is public with no
 * second marker on it.
 */

const TOKEN = 'eyJwYXlsb2FkIjoiYSJ9.signature';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';
const BYTES = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);

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

  /** The whole document arrives in one call; nothing here streams. */
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

/** The one thing the controller asks of the service, with a settable answer. */
class FakeViews {
  readonly tokens: string[] = [];
  result: DocumentViewBytes = {
    bytes: BYTES,
    contentType: 'image/png',
    sizeBytes: BYTES.length,
  };
  failure: unknown = null;

  async redeem(token: string): Promise<DocumentViewBytes> {
    this.tokens.push(token);

    if (this.failure !== null) throw this.failure;

    return this.result;
  }
}

/**
 * Same fixed-window semantics as the Redis limiter, one counter per window.
 *
 * The shared `FakeRateLimit` keys its counters by scope and identifier only, so
 * its two windows share one budget; the real limiter keeps them apart, and this
 * spec needs that to count twenty requests a minute.
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
      `${DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE}:${identifier}:${windowSeconds}`,
      hits,
    );
  }
}

function createController() {
  const views = new FakeViews();
  const rateLimit = new WindowRateLimit();

  const controller = new DocumentViewFileController(
    views as unknown as DocumentViewService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, views, rateLimit };
}

/** Runs the handler once against a fresh response, returning it and any failure. */
async function call(
  controller: DocumentViewFileController,
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

describe('DocumentViewFileController', () => {
  describe('the document', () => {
    it('serves the decrypted bytes with the headers that keep them private', async () => {
      const { controller, views } = createController();

      const { response, error } = await call(controller);

      expect(error).toBeNull();
      expect(response.statusCode).toBe(200);
      // The very buffer the record produced: same object, no copy, no stream.
      expect(response.body).toBe(BYTES);
      expect(views.tokens).toEqual([TOKEN]);
      expect(response.headers).toEqual(successHeaders(BYTES.length));
    });

    it('takes the media type from the record, not from the caller', async () => {
      const { controller, views } = createController();

      views.result = { bytes: BYTES, contentType: 'image/jpeg', sizeBytes: BYTES.length };

      const { response } = await call(
        controller,
        createRequest({ headers: { accept: 'text/html', 'content-type': 'text/html' } }),
      );

      expect(response.headers.get('content-type')).toBe('image/jpeg');
      // Never rendered as a document, whatever the caller asked for.
      expect(response.headers.get('x-content-type-options')).toBe('nosniff');
      expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
    });

    it('sends no bytes when the record names a type it must not serve', async () => {
      const { controller, views } = createController();

      views.result = {
        bytes: BYTES,
        // Not a type ingest produces; a row like this is corruption, not content.
        contentType: 'image/svg+xml' as DocumentContentType,
        sizeBytes: BYTES.length,
      };

      const { response, error } = await call(controller);

      expect(error).toBeInstanceOf(InternalServerErrorException);
      expect((error as InternalServerErrorException).getStatus()).toBe(500);
      expect(response.body).toBeUndefined();
      expect(response.headersSent).toBe(false);
      // A failed answer is still uncacheable.
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(response.headers.has('content-type')).toBe(false);
      expect(response.headers.has('content-length')).toBe(false);
    });

    it('sends no bytes when the service cannot produce them', async () => {
      const { controller, views } = createController();

      views.failure = new ServiceUnavailableException();

      const { response, error } = await call(controller);

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(response.body).toBeUndefined();
      expect(response.headersSent).toBe(false);
      expect(response.headers.has('content-length')).toBe(false);
    });
  });

  describe('the budget', () => {
    it('counts the address, in both windows, before the token is redeemed', async () => {
      const { controller, rateLimit } = createController();

      await call(controller);

      expect(rateLimit.calls).toEqual([
        {
          scope: DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...DOCUMENT_VIEW_FILE_LIMITS[0],
        },
        {
          scope: DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE,
          identifier: IP,
          ...DOCUMENT_VIEW_FILE_LIMITS[1],
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
    it('is a public GET on documents/view/:token', () => {
      const handler = DocumentViewFileController.prototype.view;

      expect(Reflect.getMetadata(PATH_METADATA, DocumentViewFileController)).toBe('documents/view');
      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(RequestMethod.GET);
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe(':token');
    });

    it('carries the public marker and no other, because the token is the credential', () => {
      const handler = DocumentViewFileController.prototype.view;

      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBe(true);
      // A role, a step-up or an identity check here would break the `<img>` that
      // follows the link, and would disagree with the basis already in the token.
      expect(Reflect.getMetadata(ROLES_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(REQUIRES_IDENTITY_VERIFIER_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBeUndefined();
    });
  });
});
