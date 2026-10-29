import { UnauthorizedException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  LOGIN_BODY,
  REGISTER_BODY,
  TEST_CONTEXT,
  TEST_NOW,
  TEST_OTHER_PHONE,
  TEST_PHONE,
  TEST_USERNAME,
  auditedActions,
  auditedMetadata,
  contextWith,
  cookieContext,
  createHarness,
  issued,
  type Harness,
} from '../../test/helpers/auth-service-harness';
import {
  SESSIONS_USER_LIMIT,
  type IssuedCredentials,
  type ListSessionsResult,
  type SessionPrincipal,
  type SessionSummary,
} from './auth.service';

const SECONDS_PER_DAY = 86_400;
const MINUTE = 60_000;

const CONTEXT = contextWith({ requestId: 'req-sessions' });

function principalOf(credentials: IssuedCredentials): SessionPrincipal {
  return { userId: credentials.userId, sessionId: credentials.sessionId };
}

function listed(result: ListSessionsResult): SessionSummary[] {
  if (result.outcome !== 'ok') {
    throw new Error(`expected a session list, received ${result.outcome}`);
  }

  return result.sessions;
}

function at(credentials: IssuedCredentials[], index: number): IssuedCredentials {
  const value = credentials[index];

  if (value === undefined) throw new Error(`no session at index ${index}`);

  return value;
}

/** Registers, then opens `extraSessions` more sessions, one minute apart. */
async function accountWithSessions(
  harness: Harness,
  extraSessions: number,
): Promise<IssuedCredentials[]> {
  const credentials = [issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT))];

  for (let index = 1; index <= extraSessions; index += 1) {
    jest.setSystemTime(new Date(TEST_NOW.getTime() + index * MINUTE));
    credentials.push(issued(await harness.service.login(LOGIN_BODY, TEST_CONTEXT)));
  }

  return credentials;
}

/** A second account, so "somebody else's session" is a real row. */
async function otherAccount(harness: Harness): Promise<IssuedCredentials> {
  harness.proof.phone = TEST_OTHER_PHONE;
  const credentials = issued(
    await harness.service.register({ ...REGISTER_BODY, username: 'other_user' }, CONTEXT),
  );
  harness.proof.phone = TEST_PHONE;

  return credentials;
}

async function isActive(harness: Harness, credentials: IssuedCredentials): Promise<boolean> {
  const active = await harness.sessions.findActiveSession(
    credentials.sessionId,
    credentials.userId,
    new Date(),
  );

  return active !== null;
}

function exhaustSessionBudget(harness: Harness, credentials: IssuedCredentials): void {
  harness.rateLimit.seed(
    'sessions-user',
    credentials.userId,
    SESSIONS_USER_LIMIT.limit,
    SESSIONS_USER_LIMIT.windowSeconds,
  );
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AuthService.listSessions', () => {
  it('lists the caller own sessions, most recently used first', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);
    const second = at(sessions, 1);

    const entries = listed(await harness.service.listSessions(principalOf(second)));

    expect(entries.map((entry) => entry.id)).toEqual([second.sessionId, at(sessions, 0).sessionId]);
    expect(entries[0]).toEqual({
      id: second.sessionId,
      deviceLabel: 'jest-agent',
      createdAt: new Date(TEST_NOW.getTime() + MINUTE).toISOString(),
      lastUsedAt: new Date(TEST_NOW.getTime() + MINUTE).toISOString(),
      expiresAt: new Date(TEST_NOW.getTime() + MINUTE + 30 * SECONDS_PER_DAY * 1_000).toISOString(),
      current: true,
    });
    expect(entries[1]?.current).toBe(false);
  });

  it('exposes no device hash and no client address', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);

    const entries = listed(await harness.service.listSessions(principalOf(at(sessions, 0))));

    expect(Object.keys(entries[0] ?? {})).toEqual([
      'id',
      'deviceLabel',
      'createdAt',
      'lastUsedAt',
      'expiresAt',
      'current',
    ]);
    expect(JSON.stringify(entries)).not.toContain(TEST_CONTEXT.ip);
    expect(JSON.stringify(entries)).not.toContain(at(sessions, 0).refreshToken);
  });

  it('hides foreign and revoked sessions', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);
    const first = at(sessions, 0);
    const second = at(sessions, 1);
    const other = await otherAccount(harness);

    await harness.service.logout(cookieContext(first.refreshToken));

    const forMe = listed(await harness.service.listSessions(principalOf(second)));
    const forOther = listed(await harness.service.listSessions(principalOf(other)));

    expect(forMe.map((entry) => entry.id)).toEqual([second.sessionId]);
    expect(forOther.map((entry) => entry.id)).toEqual([other.sessionId]);
  });

  it('throttles the shared per-user budget before reading the store', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);
    const credentials = at(sessions, 0);
    exhaustSessionBudget(harness, credentials);

    const result = await harness.service.listSessions(principalOf(credentials));

    expect(result).toEqual({
      outcome: 'throttled',
      retryAfterSeconds: SESSIONS_USER_LIMIT.windowSeconds,
    });
    expect(harness.rateLimit.calls.at(-1)?.scope).toBe('sessions-user');
  });
});

describe('AuthService.revokeSession', () => {
  it('revokes one own session, audits it and kills its cookie', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);
    const first = at(sessions, 0);
    const second = at(sessions, 1);

    const result = await harness.service.revokeSession(
      principalOf(second),
      first.sessionId,
      CONTEXT,
    );

    expect(result).toEqual({ outcome: 'revoked', current: false });
    expect(harness.sessions.revokedSessions).toEqual([
      { sessionId: first.sessionId, reason: 'user_revoked' },
    ]);
    expect(auditedMetadata(harness.audit, 'auth.session.revoked')).toMatchObject({
      sessionId: first.sessionId,
      current: false,
    });

    const rotated = harness.service.refresh(cookieContext(first.refreshToken));
    await expect(rotated).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(isActive(harness, second)).resolves.toBe(true);
  });

  it('flags the current session so the controller can clear the cookie', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);
    const first = at(sessions, 0);

    await expect(
      harness.service.revokeSession(principalOf(first), first.sessionId, CONTEXT),
    ).resolves.toEqual({ outcome: 'revoked', current: true });

    expect(auditedActions(harness.audit)).toContain('auth.session.revoked');
    await expect(isActive(harness, first)).resolves.toBe(false);
  });

  it('answers not_found for a session owned by somebody else', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);
    const other = await otherAccount(harness);

    const result = await harness.service.revokeSession(
      principalOf(at(sessions, 0)),
      other.sessionId,
      CONTEXT,
    );

    expect(result).toEqual({ outcome: 'not_found' });
    expect(harness.sessions.revokedSessions).toHaveLength(0);
    await expect(isActive(harness, other)).resolves.toBe(true);
    expect(auditedActions(harness.audit)).not.toContain('auth.session.revoked');
  });

  it('answers not_found for unknown, malformed and already revoked ids alike', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);
    const first = at(sessions, 0);
    const second = at(sessions, 1);
    const principal = principalOf(first);

    const unknown = await harness.service.revokeSession(principal, randomUUID(), CONTEXT);
    const malformed = await harness.service.revokeSession(principal, 'not-a-uuid', CONTEXT);
    const revoked = await harness.service.revokeSession(principal, second.sessionId, CONTEXT);
    const repeated = await harness.service.revokeSession(principal, second.sessionId, CONTEXT);

    expect([unknown, malformed]).toEqual([{ outcome: 'not_found' }, { outcome: 'not_found' }]);
    expect(revoked).toEqual({ outcome: 'revoked', current: false });
    // Repeating the call cannot be told apart from an id that never existed.
    expect(repeated).toEqual({ outcome: 'not_found' });
    expect(harness.sessions.revokedSessions).toHaveLength(1);
  });

  it('throttles the shared per-user budget', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);
    const first = at(sessions, 0);
    exhaustSessionBudget(harness, first);

    const result = await harness.service.revokeSession(
      principalOf(first),
      at(sessions, 1).sessionId,
      CONTEXT,
    );

    expect(result).toEqual({
      outcome: 'throttled',
      retryAfterSeconds: SESSIONS_USER_LIMIT.windowSeconds,
    });
    expect(harness.sessions.revokedSessions).toHaveLength(0);
  });
});

describe('AuthService.logoutAll', () => {
  it('revokes every session of the caller, including the current one', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 1);

    await expect(harness.service.logoutAll(principalOf(at(sessions, 1)), CONTEXT)).resolves.toEqual(
      { outcome: 'ok' },
    );

    for (const credentials of sessions) {
      await expect(isActive(harness, credentials)).resolves.toBe(false);
    }
    expect(harness.sessions.revokedSessions.map((entry) => entry.reason)).toEqual([
      'logout_all',
      'logout_all',
    ]);
    expect(auditedActions(harness.audit)).toContain('auth.logout_all');
  });

  it('leaves sessions of other accounts alone', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);
    const other = await otherAccount(harness);

    await harness.service.logoutAll(principalOf(at(sessions, 0)), CONTEXT);

    await expect(isActive(harness, other)).resolves.toBe(true);
    expect(harness.sessions.revokedSessions).toHaveLength(1);
  });

  it('throttles the shared per-user budget', async () => {
    const harness = createHarness();
    const sessions = await accountWithSessions(harness, 0);
    const credentials = at(sessions, 0);
    exhaustSessionBudget(harness, credentials);

    const result = await harness.service.logoutAll(principalOf(credentials), CONTEXT);

    expect(result).toEqual({
      outcome: 'throttled',
      retryAfterSeconds: SESSIONS_USER_LIMIT.windowSeconds,
    });
    await expect(isActive(harness, credentials)).resolves.toBe(true);
  });
});

describe('AuthService session cap', () => {
  it('revokes the oldest session when a login would exceed the cap', async () => {
    const harness = createHarness({ sessionsMaxPerUser: 2 });
    const sessions = await accountWithSessions(harness, 2);
    const first = at(sessions, 0);

    expect(harness.sessions.revokedSessions).toEqual([
      { sessionId: first.sessionId, reason: 'session_cap' },
    ]);
    await expect(isActive(harness, first)).resolves.toBe(false);
    await expect(isActive(harness, at(sessions, 2))).resolves.toBe(true);

    // The evicted session is really gone: its refresh cookie is refused.
    await expect(harness.service.refresh(cookieContext(first.refreshToken))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('keeps every session when the account is below the cap', async () => {
    const harness = createHarness({ sessionsMaxPerUser: 3 });
    const sessions = await accountWithSessions(harness, 2);

    expect(harness.sessions.revokedSessions).toHaveLength(0);

    for (const credentials of sessions) {
      await expect(isActive(harness, credentials)).resolves.toBe(true);
    }
  });
});

describe('AuthService device binding on registration', () => {
  it('binds the first session when the client sent a device key', async () => {
    const harness = createHarness();

    await harness.service.register(REGISTER_BODY, TEST_CONTEXT);

    const session = [...harness.sessions.sessions.values()][0];

    expect(session?.deviceBound).toBe(true);
    expect(session?.deviceLabel).toBe('jest-agent');
  });

  it('leaves the first session unbound when no device key was sent', async () => {
    const harness = createHarness();

    await harness.service.register(REGISTER_BODY, contextWith({ deviceKey: null }));

    expect([...harness.sessions.sessions.values()][0]?.deviceBound).toBe(false);
  });
});

describe('AuthService.register username pre-check', () => {
  it('refuses a taken username without spending the proof', async () => {
    const harness = createHarness();
    harness.sessions.seedUser({ phone: TEST_OTHER_PHONE, username: TEST_USERNAME });

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toThrow();

    // A taken name must not cost the caller their one-time code.
    expect(harness.proof.consumed).toHaveLength(0);
    expect(harness.sessions.users.size).toBe(1);
    expect(harness.sessions.sessions.size).toBe(0);
  });
});
