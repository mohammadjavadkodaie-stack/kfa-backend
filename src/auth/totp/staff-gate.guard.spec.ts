import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { SECOND_FACTOR_REQUIRED_CODE } from '../../common/errors/error-response';
import type { AuthenticatedRequest, RequestPrincipal } from '../guards/auth.guard';
import { InMemorySessionRepository } from '../in-memory-session.repository';
import { Role } from '../roles';
import type { SessionRepository } from '../session.repository';
import {
  ALLOW_WITHOUT_SECOND_FACTOR_KEY,
  AllowWithoutSecondFactor,
  StaffGateGuard,
} from './staff-gate.guard';

/**
 * The gate decides on one fact only: did *this* session ever prove a second
 * factor. Everything here checks that, the roles it stays out of, and the rule
 * that a route without the decorator is closed by default.
 */

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_SESSION_ID = '33333333-3333-4333-8333-333333333333';

const handler = (): void => undefined;
class TestController {}

function principal(
  role: Role = Role.ADMIN,
  userId: string = USER_ID,
  sessionId: string = SESSION_ID,
): RequestPrincipal {
  return { userId, sessionId, role, identityVerifier: false, expiresAtSeconds: 1_700_000_000 };
}

interface HarnessOptions {
  /** True when the route carries `@AllowWithoutSecondFactor()`. */
  readonly open?: boolean;
  readonly isPublic?: boolean;
  readonly principal?: RequestPrincipal;
  /** The stamp the session store reports; `null` means it never proved itself. */
  readonly stepupAt?: Date | null;
  /** Makes the session store fail, the way an unreachable database would. */
  readonly fails?: boolean;
}

function createHarness(options: HarnessOptions, store?: SessionRepository) {
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
      case ALLOW_WITHOUT_SECOND_FACTOR_KEY:
        return options.open;
      case IS_PUBLIC_KEY:
        return options.isPublic;
      default:
        return undefined;
    }
  });

  return {
    guard: new StaffGateGuard(
      { getAllAndOverride } as unknown as Reflector,
      store ?? ({ getStepUpAt } as unknown as SessionRepository),
    ),
    context,
    getStepUpAt,
  };
}

async function allowed(options: HarnessOptions, store?: SessionRepository): Promise<void> {
  const { guard, context } = createHarness(options, store);

  await expect(guard.canActivate(context)).resolves.toBe(true);
}

async function denied(options: HarnessOptions, store?: SessionRepository): Promise<void> {
  const { guard, context } = createHarness(options, store);

  await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
}

describe('StaffGateGuard', () => {
  it.each([Role.ADMIN, Role.OWNER])('admits a %s session that proved the factor', async (role) => {
    await allowed({ principal: principal(role), stepupAt: new Date() });
  });

  it('admits a stamp of any age: the gate asks whether it ever happened', async () => {
    await allowed({ principal: principal(), stepupAt: new Date(Date.now() - 90 * 24 * 3_600_000) });
  });

  it('refuses a staff session that never proved the factor', async () => {
    for (const role of [Role.ADMIN, Role.OWNER]) {
      await denied({ principal: principal(role), stepupAt: null });
    }
  });

  it('refuses when a route carries no decorator, so it is closed by default', async () => {
    await denied({ principal: principal() });
  });

  it('opens a route marked @AllowWithoutSecondFactor without asking the store', async () => {
    const { guard, context, getStepUpAt } = createHarness({
      open: true,
      principal: principal(),
      stepupAt: null,
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getStepUpAt).not.toHaveBeenCalled();
  });

  it('leaves a public route alone, even without a principal', async () => {
    await allowed({ isPublic: true });
  });

  it.each([Role.USER, Role.ATHLETE])('never gates a %s session', async (role) => {
    const { guard, context, getStepUpAt } = createHarness({ principal: principal(role) });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getStepUpAt).not.toHaveBeenCalled();
  });

  it('asks about the session of the token, never one named in the body', async () => {
    const { guard, context, getStepUpAt } = createHarness({
      principal: principal(),
      stepupAt: new Date(),
    });

    await guard.canActivate(context);

    expect(getStepUpAt).toHaveBeenCalledWith(SESSION_ID, USER_ID);
    expect(getStepUpAt).not.toHaveBeenCalledWith(OTHER_SESSION_ID, expect.anything());
  });

  it('fails closed when the session cannot be read', async () => {
    await denied({ principal: principal(), fails: true });
  });

  it('fails closed when a protected route has no principal', async () => {
    await denied({});
  });

  it('answers every refusal with the same actionable code and nothing else', async () => {
    const refusals: unknown[] = [];
    const cases: HarnessOptions[] = [
      { principal: principal(Role.ADMIN), stepupAt: null },
      { principal: principal(Role.OWNER), stepupAt: null },
      { principal: principal(), fails: true },
      { principal: principal() },
      {},
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
      expect(body).toEqual({ code: SECOND_FACTOR_REQUIRED_CODE });
    }

    expect(new Set(refusals.map((body) => JSON.stringify(body))).size).toBe(1);
  });

  it('keeps the metadata key stable, so the decorator and the guard agree', () => {
    expect(ALLOW_WITHOUT_SECOND_FACTOR_KEY).toBe('kfa:allowWithoutSecondFactor');
    expect(AllowWithoutSecondFactor()).toBeDefined();
  });

  describe('StaffGateGuard against the session store', () => {
    let sequence = 0;

    /** A live session of a fresh staff account, with a stamp already on it. */
    async function staffSession(): Promise<{
      repo: InMemorySessionRepository;
      owner: RequestPrincipal;
    }> {
      sequence += 1;

      const repo = new InMemorySessionRepository();
      const user = repo.seedUser({ phone: `+1415555010${sequence}`, username: `gate_${sequence}` });
      const session = await repo.createSession({
        userId: user.id,
        deviceKeyHash: 'device',
        deviceBound: false,
        deviceLabel: null,
        now: new Date(),
        sessionExpiresAt: new Date(Date.now() + 3_600_000),
        refreshTokenHash: 'refresh',
        refreshExpiresAt: new Date(Date.now() + 3_600_000),
        maxActiveSessions: 5,
      });

      repo.setUserRole(user.id, { role: Role.ADMIN });
      await repo.markStepUp(session.sessionId, user.id);

      return { repo, owner: principal(Role.ADMIN, user.id, session.sessionId) };
    }

    it('admits its own live session', async () => {
      const { repo, owner } = await staffSession();

      await allowed({ principal: owner }, repo);
    });

    it('refuses a revoked session even though it once proved itself', async () => {
      const { repo, owner } = await staffSession();

      await repo.revokeSession(owner.sessionId, 'logout', new Date());

      await denied({ principal: owner }, repo);
    });

    it('refuses a session that belongs to somebody else', async () => {
      const { repo, owner } = await staffSession();

      await denied(
        { principal: { ...owner, userId: '44444444-4444-4444-8444-444444444444' } },
        repo,
      );
    });

    it('refuses an expired session', async () => {
      sequence += 1;

      const repo = new InMemorySessionRepository();
      const user = repo.seedUser({ phone: `+1415555019${sequence}`, username: `gate_${sequence}` });
      const session = await repo.createSession({
        userId: user.id,
        deviceKeyHash: 'device',
        deviceBound: false,
        deviceLabel: null,
        now: new Date(Date.now() - 7_200_000),
        sessionExpiresAt: new Date(Date.now() - 3_600_000),
        refreshTokenHash: 'refresh',
        refreshExpiresAt: new Date(Date.now() - 3_600_000),
        maxActiveSessions: 5,
      });
      const row = repo.sessions.get(session.sessionId);

      if (row === undefined) throw new Error('missing session');

      repo.setUserRole(user.id, { role: Role.ADMIN });
      // The stamp is there; the session it sits on is not usable any more.
      row.stepupAt = new Date();

      await denied({ principal: principal(Role.ADMIN, user.id, session.sessionId) }, repo);
    });
  });
});
