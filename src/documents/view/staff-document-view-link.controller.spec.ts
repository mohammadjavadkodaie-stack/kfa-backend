import {
  HttpException,
  HttpStatus,
  NotFoundException,
  ServiceUnavailableException,
  ForbiddenException,
  type ExecutionContext,
} from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { Reflector } from '@nestjs/core';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import type { Response } from 'express';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import { ROLES_KEY } from '../../auth/decorators/roles.decorator';
import type { AuthenticatedRequest, RequestPrincipal } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import type { SessionRepository } from '../../auth/session.repository';
import { StaffGateGuard } from '../../auth/totp/staff-gate.guard';
import { STEPUP_WINDOW_MS, STEP_UP_REQUIRED_KEY, StepUpGuard } from '../../auth/totp/step-up.guard';
import {
  SECOND_FACTOR_REQUIRED_CODE,
  STEP_UP_REQUIRED_CODE,
} from '../../common/errors/error-response';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../../rate-limit/rate-limit.service';
import { DocumentViewLinkParamsDto } from './document-view-link.dto';
import type {
  DocumentViewLink,
  DocumentViewService,
  IssueViewLinkRequest,
} from './document-view.service';
import { StaffDocumentViewLinkController } from './staff-document-view-link.controller';
import { DOCUMENT_VIEW_LINK_LIMITS, DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE } from './view-link-limits';

const DOCUMENT_ID = '11111111-1111-4111-8111-111111111111';
const STAFF_ID = '22222222-2222-4222-8222-222222222222';
const REQUEST_ID = 'request-1';
const PARAMS: DocumentViewLinkParamsDto = { documentId: DOCUMENT_ID };
const HANDLER = StaffDocumentViewLinkController.prototype.issueLink;

function principal(role: Role): RequestPrincipal {
  return {
    userId: STAFF_ID,
    sessionId: 'session-1',
    role,
    identityVerifier: false,
    expiresAtSeconds: 0,
  };
}

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

function build() {
  const views = new FakeViews();
  const rateLimit = new FakeRateLimit();
  const controller = new StaffDocumentViewLinkController(
    views as unknown as DocumentViewService,
    rateLimit as unknown as RateLimitService,
  );

  return { controller, views, rateLimit };
}

/** The token-verified principal the global guards would have attached. */
function request(role: Role = Role.ADMIN): AuthenticatedRequest {
  return {
    auth: principal(role),
    headers: {},
    id: REQUEST_ID,
  } as unknown as AuthenticatedRequest;
}

/** Runs a guard that may answer synchronously, turning its throw into a rejection. */
function attempt(call: () => Promise<unknown> | boolean): Promise<unknown> {
  return Promise.resolve().then(call);
}

/** The refusal a guard or a handler raised, or a failure if it allowed. */
async function refusal(
  call: Promise<unknown> | (() => Promise<unknown> | boolean),
): Promise<HttpException> {
  try {
    await (typeof call === 'function' ? attempt(call) : call);
  } catch (error) {
    if (error instanceof HttpException) return error;

    throw error;
  }

  throw new Error('the call answered, but a refusal was expected');
}

/** Reads metadata exactly as the real `Reflector` does: handler first, class next. */
function reflectorFor(): Reflector {
  return {
    getAllAndOverride: (key: string): unknown => {
      const own = Reflect.getMetadata(key, HANDLER);

      return own === undefined ? Reflect.getMetadata(key, StaffDocumentViewLinkController) : own;
    },
  } as unknown as Reflector;
}

function contextFor(request: AuthenticatedRequest): ExecutionContext {
  return {
    getHandler: () => HANDLER,
    getClass: () => StaffDocumentViewLinkController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

/** The session row a guard reads; `'fail'` stands for an unreachable store. */
function sessionsWith(stepupAt: Date | null | 'fail'): SessionRepository {
  return {
    getStepUpAt: async (): Promise<Date | null> => {
      if (stepupAt === 'fail') throw new Error('session store is unavailable');

      return stepupAt;
    },
  } as unknown as SessionRepository;
}

describe('StaffDocumentViewLinkController', () => {
  describe('route metadata', () => {
    it('is mounted on its own staff path, apart from the owner route', () => {
      expect(Reflect.getMetadata(PATH_METADATA, StaffDocumentViewLinkController)).toBe(
        'staff/documents',
      );
      expect(Reflect.getMetadata(PATH_METADATA, HANDLER)).toBe(':documentId/view-link');
    });

    it('accepts POST only: issuing a link is not idempotent', () => {
      expect(Reflect.getMetadata(METHOD_METADATA, HANDLER)).toBe(1);
    });

    it('carries exactly one marker kind: the two staff roles', () => {
      expect(Reflect.getMetadata(ROLES_KEY, HANDLER)).toEqual([Role.ADMIN, Role.OWNER]);
      // One marker kind, per the route-marker rule: a second one would be an
      // ambiguity rather than a stricter route.
      expect(Reflect.getMetadata(AUTHENTICATED_KEY, HANDLER)).toBeUndefined();
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, HANDLER)).toBeUndefined();
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, StaffDocumentViewLinkController)).toBeUndefined();
    });

    it('demands a fresh step-up on the handler itself', () => {
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, HANDLER)).toBe(true);
    });
  });

  describe('the parameter the route accepts', () => {
    /** The same options the global pipe uses. */
    const pipe = { whitelist: true, forbidNonWhitelisted: true };

    async function errorsFor(params: Record<string, unknown>): Promise<number> {
      const dto = plainToInstance(DocumentViewLinkParamsDto, params);

      return (await validate(dto, pipe)).length;
    }

    it('takes one document id and refuses every other field', async () => {
      expect(await errorsFor({ documentId: DOCUMENT_ID })).toBe(0);
      expect(await errorsFor({ documentId: 'document-1' })).toBeGreaterThan(0);
      expect(await errorsFor({})).toBeGreaterThan(0);
      expect(await errorsFor({ documentId: DOCUMENT_ID, ownerUserId: STAFF_ID })).toBeGreaterThan(
        0,
      );
      expect(await errorsFor({ documentId: DOCUMENT_ID, staffVerified: true })).toBeGreaterThan(0);
    });
  });

  describe('the roles the route admits', () => {
    const guard = new RolesGuard(reflectorFor());

    it.each([Role.ADMIN, Role.OWNER])('admits an %s session', async (role) => {
      await expect(attempt(() => guard.canActivate(contextFor(request(role))))).resolves.toBe(true);
    });

    it.each([Role.USER, Role.ATHLETE])(
      'refuses a %s session with one generic 403',
      async (role) => {
        const error = await refusal(() => guard.canActivate(contextFor(request(role))));

        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
        expect(error.message).toBe('Forbidden');
      },
    );
  });

  describe('the second factor the route demands', () => {
    it('admits a staff session that stepped up a moment ago', async () => {
      const guard = new StepUpGuard(reflectorFor(), sessionsWith(new Date()));

      await expect(attempt(() => guard.canActivate(contextFor(request(Role.ADMIN))))).resolves.toBe(
        true,
      );
    });

    it('refuses a staff session that never stepped up', async () => {
      const guard = new StepUpGuard(reflectorFor(), sessionsWith(null));

      const error = await refusal(() => guard.canActivate(contextFor(request(Role.ADMIN))));

      expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
      expect(error.getResponse()).toEqual({ code: STEP_UP_REQUIRED_CODE });
    });

    it('refuses a step-up older than the window, and one from the future', async () => {
      for (const stamp of [
        new Date(Date.now() - STEPUP_WINDOW_MS),
        new Date(Date.now() + 60_000),
      ]) {
        const guard = new StepUpGuard(reflectorFor(), sessionsWith(stamp));

        const error = await refusal(() => guard.canActivate(contextFor(request(Role.ADMIN))));

        expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
      }
    });

    it('refuses a non-staff session even with a fresh step-up', async () => {
      const guard = new StepUpGuard(reflectorFor(), sessionsWith(new Date()));

      const error = await refusal(() => guard.canActivate(contextFor(request(Role.ATHLETE))));

      expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
    });

    it('refuses when the session store cannot be read', async () => {
      const guard = new StepUpGuard(reflectorFor(), sessionsWith('fail'));

      const error = await refusal(() => guard.canActivate(contextFor(request(Role.ADMIN))));

      expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
    });
  });

  describe('the staff gate in front of it', () => {
    const guard = new StaffGateGuard(reflectorFor(), sessionsWith(null));

    it('refuses a staff session that never proved a second factor at all', async () => {
      const error = await refusal(() => guard.canActivate(contextFor(request(Role.ADMIN))));

      expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
      expect(error.getResponse()).toEqual({ code: SECOND_FACTOR_REQUIRED_CODE });
    });

    it('leaves a non-staff session to the role check', async () => {
      await expect(attempt(() => guard.canActivate(contextFor(request(Role.USER))))).resolves.toBe(
        true,
      );
    });
  });

  describe('what the handler asks the service for', () => {
    it('answers the link and nothing else', async () => {
      const { controller } = build();

      const body = (await controller.issueLink(
        PARAMS,
        request(),
        new FakeResponse() as unknown as Response,
      )) as DocumentViewLink;

      expect(body).toEqual({ token: 'token-1', expiresInSeconds: 60 });
      expect(Object.keys(body).sort()).toEqual(['expiresInSeconds', 'token']);
    });

    it('asserts the staff basis for the caller, and only after the guards', async () => {
      const { controller, views } = build();

      await controller.issueLink(
        PARAMS,
        request(Role.OWNER),
        new FakeResponse() as unknown as Response,
      );

      expect(views.calls[0]).toEqual({
        actor: { id: STAFF_ID, role: Role.OWNER },
        request: { documentId: DOCUMENT_ID, staffVerified: true },
      });
    });

    it('refuses with 403 when no principal was attached, instead of guessing one', async () => {
      const { controller, views } = build();
      const anonymous = {
        auth: undefined,
        headers: {},
        id: REQUEST_ID,
      } as unknown as AuthenticatedRequest;

      const error = await refusal(
        controller.issueLink(PARAMS, anonymous, new FakeResponse() as unknown as Response),
      );

      expect(error).toBeInstanceOf(ForbiddenException);
      expect(views.calls).toEqual([]);
    });

    it('passes the generic 404 through unchanged, so a foreign document is not a signal', async () => {
      const { controller, views } = build();
      views.failure = new NotFoundException();

      const error = await refusal(
        controller.issueLink(PARAMS, request(), new FakeResponse() as unknown as Response),
      );

      expect(error).toBe(views.failure);
      expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(error.message).toBe('Not Found');
    });

    it('passes a missing secret or store through as one generic 503', async () => {
      const { controller, views } = build();
      views.failure = new ServiceUnavailableException();

      const error = await refusal(
        controller.issueLink(PARAMS, request(), new FakeResponse() as unknown as Response),
      );

      expect(error.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
      expect(error.message).toBe('Service Unavailable');
    });
  });

  describe('the per-user limits', () => {
    it('consumes both windows for the staff user, never for an address', async () => {
      const { controller, rateLimit } = build();

      await controller.issueLink(PARAMS, request(), new FakeResponse() as unknown as Response);

      expect(rateLimit.consumed).toEqual([
        {
          scope: DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
          identifier: STAFF_ID,
          limit: DOCUMENT_VIEW_LINK_LIMITS[0].limit,
          windowSeconds: DOCUMENT_VIEW_LINK_LIMITS[0].windowSeconds,
        },
        {
          scope: DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
          identifier: STAFF_ID,
          limit: DOCUMENT_VIEW_LINK_LIMITS[1].limit,
          windowSeconds: DOCUMENT_VIEW_LINK_LIMITS[1].windowSeconds,
        },
      ]);
    });

    it('answers the shared 429 envelope and never reaches the service', async () => {
      const { controller, rateLimit, views } = build();
      rateLimit.allowed = false;
      rateLimit.retryAfterSeconds = 6.2;

      const response = new FakeResponse();
      const body = await controller.issueLink(PARAMS, request(), response as unknown as Response);

      expect(body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: REQUEST_ID,
      });
      expect(response.headers.get('Retry-After')).toBe('7');
      expect(response.statusCode).toBe(HttpStatus.TOO_MANY_REQUESTS);
      expect(views.calls).toEqual([]);
      expect(rateLimit.consumed).toHaveLength(1);
    });
  });
});
