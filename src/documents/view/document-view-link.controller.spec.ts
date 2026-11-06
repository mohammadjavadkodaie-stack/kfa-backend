import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import type { Response } from 'express';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest, RequestPrincipal } from '../../auth/guards/auth.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../../rate-limit/rate-limit.service';
import { DocumentViewLinkController } from './document-view-link.controller';
import { DocumentViewLinkParamsDto } from './document-view-link.dto';
import type {
  DocumentViewLink,
  DocumentViewService,
  IssueViewLinkRequest,
} from './document-view.service';
import { DOCUMENT_VIEW_LINK_LIMITS, DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE } from './view-link-limits';

const DOCUMENT_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = 'request-1';
const PARAMS: DocumentViewLinkParamsDto = { documentId: DOCUMENT_ID };

const PRINCIPAL: RequestPrincipal = {
  userId: USER_ID,
  sessionId: 'session-1',
  role: Role.ATHLETE,
  identityVerifier: false,
  expiresAtSeconds: 0,
};

class FakeViews {
  readonly calls: { actor: PolicySubject; request: IssueViewLinkRequest }[] = [];
  failure: Error | null = null;

  async issueLink(actor: PolicySubject, request: IssueViewLinkRequest): Promise<DocumentViewLink> {
    this.calls.push({ actor, request });

    if (this.failure !== null) throw this.failure;

    return { token: 'token-1', expiresInSeconds: 60 };
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
  const views = new FakeViews();
  const rateLimit = new FakeRateLimit();
  const controller = new DocumentViewLinkController(
    views as unknown as DocumentViewService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, views, rateLimit };
}

interface RequestOptions {
  readonly principal?: RequestPrincipal | undefined;
}

/** The token-verified principal the global guards would have attached. */
function request(options: RequestOptions = {}): AuthenticatedRequest {
  return {
    auth: 'principal' in options ? options.principal : PRINCIPAL,
    headers: {},
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

describe('DocumentViewLinkController', () => {
  describe('route metadata', () => {
    const handler = DocumentViewLinkController.prototype.issueOwnLink;

    it('is mounted on the athlete path, below the documents the caller owns', () => {
      expect(Reflect.getMetadata(PATH_METADATA, DocumentViewLinkController)).toBe('athlete');
      expect(Reflect.getMetadata(PATH_METADATA, handler)).toBe('documents/:documentId/view-link');
    });

    it('accepts POST only: issuing a link is not idempotent', () => {
      expect(Reflect.getMetadata(METHOD_METADATA, handler)).toBe(1);
    });

    it('is authenticated and never public', () => {
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBeUndefined();
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, DocumentViewLinkController)).toBeUndefined();
    });
  });

  describe('the parameter the route accepts', () => {
    /** The same options the global pipe uses. */
    const pipe = { whitelist: true, forbidNonWhitelisted: true };

    async function errorsFor(params: Record<string, unknown>): Promise<number> {
      const dto = plainToInstance(DocumentViewLinkParamsDto, params);

      return (await validate(dto, pipe)).length;
    }

    it('takes the id of one document', async () => {
      expect(await errorsFor({ documentId: DOCUMENT_ID })).toBe(0);
    });

    it('refuses anything that is not a uuid', async () => {
      for (const documentId of [
        'document-1',
        '',
        '11111111-1111-4111-8111-11111111111',
        `${DOCUMENT_ID}x`,
        'not-a-uuid-1111-4111-8111-111111111111',
        42,
      ]) {
        expect(await errorsFor({ documentId })).toBeGreaterThan(0);
      }
    });

    it('refuses a missing id, so nothing is looked up by accident', async () => {
      expect(await errorsFor({})).toBeGreaterThan(0);
    });

    it('refuses any other field, so an owner cannot be addressed', async () => {
      expect(await errorsFor({ documentId: DOCUMENT_ID, ownerUserId: USER_ID })).toBeGreaterThan(0);
      expect(await errorsFor({ documentId: DOCUMENT_ID, viewerUserId: USER_ID })).toBeGreaterThan(
        0,
      );
      expect(await errorsFor({ documentId: DOCUMENT_ID, objectKey: 'anything' })).toBeGreaterThan(
        0,
      );
      expect(await errorsFor({ documentId: DOCUMENT_ID, fileName: 'id.png' })).toBeGreaterThan(0);
      expect(await errorsFor({ documentId: DOCUMENT_ID, staffVerified: true })).toBeGreaterThan(0);
    });
  });

  describe('an authenticated caller reading their own document', () => {
    it('answers the link and nothing else: a token and its lifetime', async () => {
      const { controller, views } = build();

      const body = (await controller.issueOwnLink(
        PARAMS,
        request(),
        new FakeResponse() as unknown as Response,
      )) as DocumentViewLink;

      expect(body).toEqual({ token: 'token-1', expiresInSeconds: 60 });
      expect(Object.keys(body).sort()).toEqual(['expiresInSeconds', 'token']);
      expect(views.calls).toHaveLength(1);
    });

    it('asks for the caller as the viewer and never asserts a staff verification', async () => {
      const { controller, views } = build();

      await controller.issueOwnLink(PARAMS, request(), new FakeResponse() as unknown as Response);

      expect(views.calls[0]).toEqual({
        actor: { id: USER_ID, role: Role.ATHLETE },
        request: { documentId: DOCUMENT_ID },
      });
      // The owner route enforces neither StaffGate nor a step-up, so it can never
      // produce the staff basis - not even for a staff caller.
      expect('staffVerified' in (views.calls[0] ?? { request: {} }).request).toBe(false);
    });
  });

  it('refuses with 403 when no principal was attached, instead of guessing one', async () => {
    const { controller, views } = build();

    const error = await refusal(
      controller.issueOwnLink(
        PARAMS,
        request({ principal: undefined }),
        new FakeResponse() as unknown as Response,
      ),
    );

    expect(error).toBeInstanceOf(ForbiddenException);
    expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
    expect(views.calls).toEqual([]);
  });

  describe('the service refuses', () => {
    it('passes the generic 404 through unchanged', async () => {
      const { controller, views } = build();
      views.failure = new NotFoundException();

      const error = await refusal(
        controller.issueOwnLink(PARAMS, request(), new FakeResponse() as unknown as Response),
      );

      // The same object: the route never rewrites a decision into another answer.
      expect(error).toBe(views.failure);
      expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(error.message).toBe('Not Found');
    });

    it('passes a missing secret or store through as one generic 503', async () => {
      const { controller, views } = build();
      views.failure = new ServiceUnavailableException();

      const error = await refusal(
        controller.issueOwnLink(PARAMS, request(), new FakeResponse() as unknown as Response),
      );

      expect(error.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
      expect(error.message).toBe('Service Unavailable');
      expect(error.message).not.toContain('DOCUMENT_VIEW_TOKEN_SECRET');
      expect(error.message).not.toContain('redis');
    });
  });

  describe('the per-user limits', () => {
    it('consumes both windows for the token owner, never for an address', async () => {
      const { controller, rateLimit } = build();

      await controller.issueOwnLink(PARAMS, request(), new FakeResponse() as unknown as Response);

      expect(rateLimit.consumed).toEqual([
        {
          scope: DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
          identifier: USER_ID,
          limit: 10,
          windowSeconds: 60,
        },
        {
          scope: DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
          identifier: USER_ID,
          limit: 30,
          windowSeconds: 3_600,
        },
      ]);
      expect(DOCUMENT_VIEW_LINK_LIMITS).toHaveLength(2);
    });

    it('checks the burst window first and stops there', async () => {
      const { controller, rateLimit, views } = build();
      rateLimit.allowed = false;

      await controller.issueOwnLink(PARAMS, request(), new FakeResponse() as unknown as Response);

      expect(rateLimit.consumed).toHaveLength(1);
      expect(views.calls).toEqual([]);
    });

    it('answers the shared 429 envelope with the retry hint', async () => {
      const { controller, rateLimit, views } = build();
      rateLimit.allowed = false;
      rateLimit.retryAfterSeconds = 6.2;

      const response = new FakeResponse();
      const body = await controller.issueOwnLink(
        PARAMS,
        request(),
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
      expect(views.calls).toEqual([]);
    });
  });
});
