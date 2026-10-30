import { UnauthorizedException } from '@nestjs/common';
import {
  LOGIN_BODY,
  TEST_CONTEXT,
  TEST_NOW,
  TEST_PHONE,
  TEST_USERNAME,
  auditedActions,
  cookieContext,
  createHarness,
  issued,
} from '../../test/helpers/auth-service-harness';
import { Role } from './roles';

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

/** In-memory clock: the service reads the wall clock, so the test moves it. */
function clock(offsetMs: number): void {
  jest.setSystemTime(new Date(TEST_NOW.getTime() + offsetMs));
}

function loginAs(role: Role) {
  const harness = createHarness();
  harness.sessions.seedUser({ phone: TEST_PHONE, username: TEST_USERNAME, role });

  return harness.service.login(LOGIN_BODY, TEST_CONTEXT).then((result) => ({
    harness,
    credentials: issued(result),
  }));
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AuthService staff sessions', () => {
  it.each([Role.ADMIN, Role.OWNER])('caps a new %s session at the staff lifetime', async (role) => {
    const { harness, credentials } = await loginAs(role);

    expect(harness.sessions.sessions.get(credentials.sessionId)?.expiresAt).toEqual(
      new Date(TEST_NOW.getTime() + 12 * HOUR),
    );
    // The refresh cookie cannot outlive the shortened session either.
    expect(credentials.refreshMaxAgeSeconds).toBe(12 * 3_600);
  });

  it.each([Role.USER, Role.ATHLETE])('keeps the normal lifetime for %s', async (role) => {
    const { harness, credentials } = await loginAs(role);

    expect(harness.sessions.sessions.get(credentials.sessionId)?.expiresAt).toEqual(
      new Date(TEST_NOW.getTime() + 30 * DAY),
    );
    expect(credentials.refreshMaxAgeSeconds).toBe(14 * 86_400);
  });

  it.each([Role.ADMIN, Role.OWNER])(
    'refuses an idle %s refresh and revokes the session',
    async (role) => {
      const { harness, credentials } = await loginAs(role);

      clock(31 * MINUTE);

      await expect(
        harness.service.refresh(cookieContext(credentials.refreshToken)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(harness.sessions.revokedSessions).toEqual([
        { sessionId: credentials.sessionId, reason: 'idle_timeout' },
      ]);
      expect(auditedActions(harness.audit)).toContain('auth.refresh.idle_timeout');
    },
  );

  it('slides the idle window on rotation without moving the absolute cap', async () => {
    const { harness, credentials } = await loginAs(Role.ADMIN);

    clock(29 * MINUTE);

    const first = issued(await harness.service.refresh(cookieContext(credentials.refreshToken)));

    expect(harness.sessions.sessions.get(credentials.sessionId)?.expiresAt).toEqual(
      new Date(TEST_NOW.getTime() + 12 * HOUR),
    );

    // Active again 29 minutes later: inside the window, so still allowed.
    clock(58 * MINUTE);

    const second = issued(await harness.service.refresh(cookieContext(first.refreshToken)));

    expect(harness.sessions.revokedSessions).toHaveLength(0);

    // One minute past the window opened by the last rotation.
    clock(89 * MINUTE);

    await expect(
      harness.service.refresh(cookieContext(second.refreshToken)),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(harness.sessions.revokedSessions).toEqual([
      { sessionId: credentials.sessionId, reason: 'idle_timeout' },
    ]);
  });

  it('still refreshes a USER session that sat idle past the staff limit', async () => {
    const { harness, credentials } = await loginAs(Role.USER);

    clock(31 * MINUTE);

    const rotated = issued(await harness.service.refresh(cookieContext(credentials.refreshToken)));

    expect(rotated.sessionId).toBe(credentials.sessionId);
    expect(harness.sessions.revokedSessions).toHaveLength(0);
  });
});
