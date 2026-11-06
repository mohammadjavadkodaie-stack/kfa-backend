import { HttpException, HttpStatus, ServiceUnavailableException } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { DocumentKind } from '@prisma/client';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import type { Response } from 'express';
import { AUTHENTICATED_KEY } from '../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest, RequestPrincipal } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../rate-limit/rate-limit.service';
import {
  DOCUMENT_KINDS,
  DOCUMENT_UPLOAD_LIMITS,
  DOCUMENT_UPLOAD_PATH,
  DOCUMENT_UPLOAD_RATE_LIMIT_SCOPE,
  DocumentUploadController,
  DocumentUploadQueryDto,
} from './document-upload.controller';
import { DocumentIngestError } from './ingest/ingest.errors';
import { buildPng, TEXT_CHUNK } from './ingest/testing/image-fixtures';
import type {
  DocumentUploadRequest,
  DocumentUploadService,
  DocumentUploadView,
} from './records/document-upload.service';

const USER_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = 'request-1';
/** A valid PNG with one comment chunk: the service never sees it here, it is only bytes. */
const PNG = buildPng({ chunks: [TEXT_CHUNK] });
const QUERY: DocumentUploadQueryDto = { kind: 'NATIONAL_ID' };

const PRINCIPAL: RequestPrincipal = {
  userId: USER_ID,
  sessionId: 'session-1',
  role: Role.ATHLETE,
  identityVerifier: false,
  expiresAtSeconds: 0,
};

class FakeUploads {
  readonly calls: { actor: PolicySubject; request: DocumentUploadRequest }[] = [];
  refuses = false;

  async upload(actor: PolicySubject, request: DocumentUploadRequest): Promise<DocumentUploadView> {
    this.calls.push({ actor, request });

    if (this.refuses) throw new DocumentIngestError();

    return {
      id: 'document-1',
      kind: request.kind,
      contentType: 'image/png',
      sizeBytes: request.bytes.length,
    };
  }
}

class FakeRateLimit {
  readonly consumed: ConsumeRateLimitInput[] = [];
  allowed = true;
  retryAfterSeconds = 0;

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    this.consumed.push(input);

    return {
      allowed: this.allowed,
      remaining: this.allowed ? 1 : 0,
      retryAfterSeconds: this.retryAfterSeconds,
    };
  }
}

class FakeResponse {
  readonly headers = new Map<string, string>();
  statusCode = HttpStatus.OK;

  setHeader(name: string, value: string): this {
    this.headers.set(name, value);

    return this;
  }

  status(code: number): this {
    this.statusCode = code;

    return this;
  }
}

/** One controller with the two fakes behind it, fresh per test. */
function build() {
  const uploads = new FakeUploads();
  const rateLimit = new FakeRateLimit();
  const controller = new DocumentUploadController(
    uploads as unknown as DocumentUploadService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, uploads, rateLimit };
}

interface RequestOptions {
  readonly principal?: RequestPrincipal | undefined;
  /** Omitted means "no Content-Type header at all". */
  readonly contentType?: string;
  readonly body?: unknown;
}

function request(options: RequestOptions = {}): AuthenticatedRequest {
  const headers: Record<string, string> = {};

  if (options.contentType !== undefined) headers['content-type'] = options.contentType;

  return {
    auth: 'principal' in options ? options.principal : PRINCIPAL,
    headers,
    body: 'body' in options ? options.body : PNG,
    id: REQUEST_ID,
  } as unknown as AuthenticatedRequest;
}

/** The refusal a handler raised, or a failure if it did not refuse at all. */
async function refusal(promise: Promise<unknown>): Promise<HttpException> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof HttpException) return error;

    throw error;
  }

  throw new Error('the route answered, but a refusal was expected');
}

async function statusOf(promise: Promise<unknown>): Promise<number> {
  return (await refusal(promise)).getStatus();
}

describe('DocumentUploadController', () => {
  describe('route metadata', () => {
    const handler = DocumentUploadController.prototype.upload;

    it('is mounted on the athlete path, one segment below it', () => {
      expect(Reflect.getMetadata(PATH_METADATA, DocumentUploadController)).toBe('athlete');
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe('documents');
      // The parser in `configureApp` is bound to the same path, so the two cannot drift.
      expect(DOCUMENT_UPLOAD_PATH).toBe('/athlete/documents');
    });

    it('accepts POST only', () => {
      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(1);
    });

    it('is authenticated and never public', () => {
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, DocumentUploadController)).toBeUndefined();
    });
  });

  describe('the query the route accepts', () => {
    /** The same options the global pipe uses. */
    const pipe = { whitelist: true, forbidNonWhitelisted: true };

    async function errorsFor(query: Record<string, unknown>): Promise<number> {
      const dto = plainToInstance(DocumentUploadQueryDto, query);

      return (await validate(dto, pipe)).length;
    }

    it('takes the three kinds the database knows', async () => {
      for (const kind of ['NATIONAL_ID', 'MEDAL', 'CERTIFICATE']) {
        expect(await errorsFor({ kind })).toBe(0);
      }
    });

    it('accepts exactly the values of the generated DocumentKind enum', async () => {
      // One source of truth: the list the route publishes is the generated enum,
      // so a value the column gains or loses cannot leave the two disagreeing.
      expect([...DOCUMENT_KINDS]).toEqual(Object.values(DocumentKind));

      for (const kind of Object.values(DocumentKind)) {
        expect(await errorsFor({ kind })).toBe(0);
      }

      // The DTO enforces the same set, not merely the constant above.
      expect(Object.values(DocumentKind)).toContain('NATIONAL_ID');
      expect(Object.values(DocumentKind)).toContain('MEDAL');
      expect(Object.values(DocumentKind)).toContain('CERTIFICATE');
      expect(Object.values(DocumentKind)).not.toContain('PASSPORT');
    });

    it('refuses an unknown or a differently cased kind', async () => {
      expect(await errorsFor({ kind: 'PASSPORT' })).toBeGreaterThan(0);
      expect(await errorsFor({ kind: 'national_id' })).toBeGreaterThan(0);
      expect(await errorsFor({ kind: '' })).toBeGreaterThan(0);
    });

    it('refuses a missing kind', async () => {
      expect(await errorsFor({})).toBeGreaterThan(0);
    });

    it('refuses any other parameter, so an owner cannot be addressed', async () => {
      expect(await errorsFor({ kind: 'MEDAL', ownerUserId: USER_ID })).toBeGreaterThan(0);
      expect(await errorsFor({ kind: 'MEDAL', userId: USER_ID })).toBeGreaterThan(0);
      expect(await errorsFor({ kind: 'MEDAL', objectKey: 'anything' })).toBeGreaterThan(0);
      expect(await errorsFor({ kind: 'MEDAL', fileName: 'id.png' })).toBeGreaterThan(0);
    });
  });

  describe('a successful upload', () => {
    it('hands the token owner, the kind, the bytes and the declared type to the service', async () => {
      const { controller, uploads } = build();

      const view = await controller.upload(
        QUERY,
        request({ contentType: 'image/png' }),
        new FakeResponse() as unknown as Response,
      );

      expect(uploads.calls).toHaveLength(1);
      expect(uploads.calls[0]?.actor).toEqual({ id: USER_ID, role: Role.ATHLETE });
      expect(uploads.calls[0]?.request).toEqual({
        kind: 'NATIONAL_ID',
        bytes: PNG,
        claimedMime: 'image/png',
      });
      expect(view).toEqual({
        id: 'document-1',
        kind: 'NATIONAL_ID',
        contentType: 'image/png',
        sizeBytes: PNG.length,
      });
    });

    it('keeps the declared type verbatim, parameters included', async () => {
      const { controller, uploads } = build();

      await controller.upload(
        QUERY,
        request({ contentType: 'IMAGE/PNG; charset=binary' }),
        new FakeResponse() as unknown as Response,
      );

      expect(uploads.calls[0]?.request.claimedMime).toBe('IMAGE/PNG; charset=binary');
    });

    it('answers with the four fields the service returned and nothing else', async () => {
      const { controller } = build();

      const view = await controller.upload(
        QUERY,
        request({ contentType: 'image/png' }),
        new FakeResponse() as unknown as Response,
      );

      expect(Object.keys(view).sort()).toEqual(['contentType', 'id', 'kind', 'sizeBytes']);
    });

    it('does not ignore a missing principal', async () => {
      const { controller } = build();

      expect(
        await statusOf(
          controller.upload(
            QUERY,
            request({ principal: undefined, contentType: 'image/png' }),
            new FakeResponse() as unknown as Response,
          ),
        ),
      ).toBe(HttpStatus.FORBIDDEN);
    });
  });

  describe('a body the route will not read', () => {
    /** Everything the raw parser skips, plus the two types it does not know. */
    const NOT_AN_UPLOAD = [
      'text/plain',
      'text/html',
      'application/json',
      'application/octet-stream',
      'application/pdf',
      'multipart/form-data; boundary=----x',
      'image/gif',
      'image/webp',
    ];

    it('answers 415 for every media type outside the two the parser buffers', async () => {
      for (const contentType of NOT_AN_UPLOAD) {
        const { controller, uploads, rateLimit } = build();

        expect(
          await statusOf(
            controller.upload(
              QUERY,
              request({ contentType }),
              new FakeResponse() as unknown as Response,
            ),
          ),
        ).toBe(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        // A request that was never parsed costs nothing and reaches nothing.
        expect(rateLimit.consumed).toEqual([]);
        expect(uploads.calls).toEqual([]);
      }
    });

    it('answers 415 when no Content-Type header was sent at all', async () => {
      const { controller, uploads } = build();

      expect(
        await statusOf(
          controller.upload(
            QUERY,
            request({ body: PNG }),
            new FakeResponse() as unknown as Response,
          ),
        ),
      ).toBe(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
      expect(uploads.calls).toEqual([]);
    });

    it('answers 422 when the parser left nothing, whatever the header says', async () => {
      const bodies: unknown[] = [Buffer.alloc(0), undefined, null, '', {}, [], 'not bytes'];

      for (const body of bodies) {
        const { controller, uploads, rateLimit } = build();

        expect(
          await statusOf(
            controller.upload(
              QUERY,
              request({ contentType: 'image/png', body }),
              new FakeResponse() as unknown as Response,
            ),
          ),
        ).toBe(HttpStatus.UNPROCESSABLE_ENTITY);
        // An empty body is a request that cannot succeed, so it is not charged either.
        expect(rateLimit.consumed).toEqual([]);
        expect(uploads.calls).toEqual([]);
      }
    });
  });

  describe('the pipeline refuses', () => {
    it('answers one generic 422, never the pipeline message', async () => {
      const { controller, uploads } = build();
      uploads.refuses = true;

      const error = await refusal(
        controller.upload(
          QUERY,
          request({ contentType: 'image/png' }),
          new FakeResponse() as unknown as Response,
        ),
      );

      expect(error.getStatus()).toBe(HttpStatus.UNPROCESSABLE_ENTITY);
      expect(error.message).toBe('Unprocessable Entity');
      expect(error.message).not.toBe(new DocumentIngestError().message);
      // It ran: the decision needs the file, so the service was reached once.
      expect(uploads.calls).toHaveLength(1);
    });

    it('lets an infrastructure failure through unchanged', async () => {
      const { controller, uploads } = build();
      uploads.upload = () => Promise.reject(new ServiceUnavailableException());

      const error = await refusal(
        controller.upload(
          QUERY,
          request({ contentType: 'image/png' }),
          new FakeResponse() as unknown as Response,
        ),
      );

      expect(error.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
      expect(error.message).toBe('Service Unavailable');
    });
  });

  describe('the per-user limits', () => {
    it('consumes both windows for the token owner, never for an address', async () => {
      const { controller, rateLimit } = build();

      await controller.upload(
        QUERY,
        request({ contentType: 'image/png' }),
        new FakeResponse() as unknown as Response,
      );

      expect(rateLimit.consumed).toEqual([
        {
          scope: DOCUMENT_UPLOAD_RATE_LIMIT_SCOPE,
          identifier: USER_ID,
          limit: 3,
          windowSeconds: 60,
        },
        {
          scope: DOCUMENT_UPLOAD_RATE_LIMIT_SCOPE,
          identifier: USER_ID,
          limit: 10,
          windowSeconds: 3_600,
        },
      ]);
      expect(DOCUMENT_UPLOAD_LIMITS).toHaveLength(2);
    });

    it('checks the burst window first and stops there', async () => {
      const { controller, rateLimit, uploads } = build();
      rateLimit.allowed = false;

      await controller.upload(
        QUERY,
        request({ contentType: 'image/png' }),
        new FakeResponse() as unknown as Response,
      );

      expect(rateLimit.consumed).toHaveLength(1);
      expect(uploads.calls).toEqual([]);
    });

    it('answers the shared 429 envelope with the retry hint', async () => {
      const { controller, uploads, rateLimit } = build();
      rateLimit.allowed = false;
      rateLimit.retryAfterSeconds = 6.2;

      const response = new FakeResponse();
      const body = await controller.upload(
        QUERY,
        request({ contentType: 'image/png' }),
        response as unknown as Response,
      );

      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      // Rounded up and never below one, exactly like every other limited route.
      expect(response.headers.get('Retry-After')).toBe('7');
      expect(response.statusCode).toBe(HttpStatus.TOO_MANY_REQUESTS);
      expect(uploads.calls).toEqual([]);
    });
  });
});
