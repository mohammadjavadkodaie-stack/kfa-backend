import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { STEP_UP_REQUIRED_CODE } from '../../common/errors/error-response';
import type { AuthenticatedRequest, RequestPrincipal } from '../guards/auth.guard';
import { Role } from '../roles';
import type { SessionRepository } from '../session.repository';
import {
  RequireStepUp,
  STEPUP_WINDOW_MS,
  STEP_UP_REQUIRED_KEY,
  StepUpGuard,
} from './step-up.guard';

/**
 * The step-up guard decides on two facts only: who the token says the caller is
 * and when *that* session last proved a second factor. Everything here checks
 * one of the two, plus the rule that every refusal is the same bytes.
 */

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_SESSION_ID = '33333333-3333-4333-8333-333333333333';

const handler = (): void => undefined;
class TestController {}

function principal(role: Role = Role.ADMIN): RequestPrincipal {
  return {
    userId: USER_ID,
    sessionId: SESSION_ID,
    role,
    identityVerifier: false,
    expiresAtSeconds: 1_700_000_000,
  };
}

interface HarnessOptions {
  readonly required?: boolean;
  readonly isPublic?: boolean;
  readonly principal?: RequestPrincipal;
  /** The stamp the session store reports; `null` means it never stepped up. */
  readonly stepupAt?: Date | null;
  /** Makes the session store fail, the way an unreachable database would. */
  readonly fails?: boolean;
}

function createHarness(options: HarnessOptions) {
  const getStepUpAt = jest.fn(async () => {
    if (options.fails === true) throw new Error('session store unavailable');

    return options.stepupAt ?? null;
  });

  const request = {
    // A caller-controlled session id must never be used.
    body: { sessionId: OTHER_SESSION_ID },
    headers: {},
  } as unknown as AuthenticatedRequest;

  if (options.principal !== undefined) {
    request.auth = options.principal;
  }

  const context = {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;

  const getAllAndOverride = jest.fn((key: string, _targets: unknown[]) => {
    switch (key) {
      case STEP_UP_REQUIRED_KEY:
        return options.required;
      case IS_PUBLIC_KEY:
        return options.isPublic;
      default:
        return undefined;
    }
  });

  return {
    guard: new StepUpGuard(
      { getAllAndOverride } as unknown as Reflector,
      { getStepUpAt } as unknown as SessionRepository,
    ),
    context,
    getStepUpAt,
  };
}

async function allowed(options: HarnessOptions): Promise<void> {
  const { guard, context } = createHarness(options);

  await expect(guard.canActivate(context)).resolves.toBe(true);
}

async function denied(options: HarnessOptions): Promise<void> {
  const { guard, context } = createHarness(options);

  await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
}

describe('StepUpGuard', () => {
  it('does nothing on a route that does not require a step-up', async () => {
    const { guard, context, getStepUpAt } = createHarness({ required: false });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getStepUpAt).not.toHaveBeenCalled();
  });

  it('does nothing on a @Public route, even when the metadata is present', async () => {
    const { guard, context, getStepUpAt } = createHarness({ required: true, isPublic: true });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getStepUpAt).not.toHaveBeenCalled();
  });

  it('admits a staff session that stepped up less than five minutes ago', async () => {
    for (const role of [Role.ADMIN, Role.OWNER]) {
      await allowed({
        required: true,
        principal: principal(role),
        stepupAt: new Date(Date.now() - (STEPUP_WINDOW_MS - 1_000)),
      });
    }
  });

  it('refuses a session that never stepped up', async () => {
    await denied({ required: true, principal: principal(), stepupAt: null });
  });

  it('refuses a stamp at or past the window', async () => {
    for (const age of [STEPUP_WINDOW_MS, STEPUP_WINDOW_MS + 1_000, 3_600_000]) {
      await denied({
        required: true,
        principal: principal(),
        stepupAt: new Date(Date.now() - age),
      });
    }
  });

  it('refuses a stamp from the future: a clock skew is not freshness', async () => {
    await denied({
      required: true,
      principal: principal(),
      stepupAt: new Date(Date.now() + 60_000),
    });
  });

  it.each([Role.USER, Role.ATHLETE])(
    'refuses %s even with a fresh stamp, because sensitive actions are staff-only',
    async (role) => {
      await denied({ required: true, principal: principal(role), stepupAt: new Date() });
    },
  );

  it('asks about the session of the token, never one named in the body', async () => {
    const { guard, context, getStepUpAt } = createHarness({
      required: true,
      principal: principal(),
      stepupAt: new Date(),
    });

    await guard.canActivate(context);

    expect(getStepUpAt).toHaveBeenCalledWith(SESSION_ID, USER_ID);
    expect(getStepUpAt).not.toHaveBeenCalledWith(OTHER_SESSION_ID, expect.anything());
  });

  it('fails closed when the session cannot be read', async () => {
    await denied({ required: true, principal: principal(), fails: true });
  });

  it('fails closed when a protected route has no principal', async () => {
    await denied({ required: true });
  });

  it('answers every refusal with the same actionable code and nothing else', async () => {
    const refusals: unknown[] = [];
    const cases: HarnessOptions[] = [
      { required: true, principal: principal(), stepupAt: null },
      { required: true, principal: principal(), stepupAt: new Date(Date.now() - STEPUP_WINDOW_MS) },
      { required: true, principal: principal(Role.USER), stepupAt: new Date() },
      { required: true, principal: principal(), fails: true },
      { required: true },
    ];

    for (const options of cases) {
      const { guard, context } = createHarness(options);

      try {
        await guard.canActivate(context);
        throw new Error('the guard admitted a request it should have refused');
      } catch (error) {
        if (!(error instanceof ForbiddenException)) throw error;

        expect(error.getStatus()).toBe(403);
        refusals.push(error.getResponse());
      }
    }

    expect(refusals).toHaveLength(cases.length);

    for (const body of refusals) {
      expect(body).toEqual({ code: STEP_UP_REQUIRED_CODE });
    }

    expect(new Set(refusals.map((body) => JSON.stringify(body))).size).toBe(1);
  });

  it('keeps the metadata key stable, so the decorator and the guard agree', () => {
    expect(STEP_UP_REQUIRED_KEY).toBe('kfa:requireStepUp');
    expect(RequireStepUp()).toBeDefined();
  });
});
