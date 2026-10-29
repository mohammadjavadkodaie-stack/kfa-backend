import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import {
  REGISTER_BODY,
  TEST_CONTEXT,
  TEST_NOW,
  auditedActions,
  contextWith,
  cookieContext,
  createHarness,
  issued,
  throttled,
  type Harness,
} from '../../test/helpers/auth-service-harness';
import { LOGOUT_IP_LIMIT, REFRESH_IP_LIMIT } from './auth.service';
import { generateRefreshToken, hashRefreshToken, REFRESH_COOKIE_NAME } from './token/refresh-token';

const SECONDS_PER_DAY = 86_400;

async function registered(): Promise<{
  harness: Harness;
  refreshToken: string;
  sessionId: string;
}> {
  const harness = createHarness();
  const credentials = issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT));

  return { harness, refreshToken: credentials.refreshToken, sessionId: credentials.sessionId };
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AuthService.refresh', () => {
  it('rotates the cookie and issues a new access token for the same session', async () => {
    const { harness, refreshToken, sessionId } = await registered();

    const credentials = issued(await harness.service.refresh(cookieContext(refreshToken)));
    const session = harness.sessions.sessions.get(sessionId);

    expect(credentials.sessionId).toBe(sessionId);
    expect(credentials.refreshToken).not.toBe(refreshToken);
    expect(credentials.expiresIn).toBe(600);
    expect(harness.sessions.sessions.size).toBe(1);
    expect(session?.lastUsedAt).toEqual(TEST_NOW);
    expect(harness.sessions.refreshTokens.get(hashRefreshToken(refreshToken))?.usedAt).toEqual(
      TEST_NOW,
    );
    expect(harness.sessions.refreshTokens.has(hashRefreshToken(credentials.refreshToken))).toBe(
      true,
    );
  });

  it('caps the next cookie by what is left of the absolute session', async () => {
    const harness = createHarness({ sessionAbsoluteDays: 1 });
    const credentials = issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT));

    jest.setSystemTime(new Date(TEST_NOW.getTime() + 12 * 3_600 * 1_000));

    const rotated = issued(await harness.service.refresh(cookieContext(credentials.refreshToken)));

    expect(rotated.refreshMaxAgeSeconds).toBe(SECONDS_PER_DAY - 12 * 3_600);
  });

  it('rejects missing, malformed and unknown cookies with the same 401', async () => {
    const { harness } = await registered();

    await expect(harness.service.refresh(TEST_CONTEXT)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    await expect(
      harness.service.refresh(contextWith({ cookieHeader: 'other=1' })),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(harness.service.refresh(cookieContext('too-short'))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    await expect(
      harness.service.refresh(cookieContext(generateRefreshToken())),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('revokes every session when a spent token is replayed', async () => {
    const { harness, refreshToken, sessionId } = await registered();
    const rotated = issued(await harness.service.refresh(cookieContext(refreshToken)));

    await expect(harness.service.refresh(cookieContext(refreshToken))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(harness.sessions.revokedSessions).toEqual([{ sessionId, reason: 'refresh_reuse' }]);
    expect(auditedActions(harness.audit)).toContain('auth.refresh.reused');
    // The winner of the race is logged out too: the cookie may be stolen.
    await expect(
      harness.service.refresh(cookieContext(rotated.refreshToken)),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('revokes the session when the device key does not match', async () => {
    const { harness, refreshToken, sessionId } = await registered();

    await expect(
      harness.service.refresh(cookieContext(refreshToken, { deviceKey: 'device-2' })),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(harness.sessions.revokedSessions).toEqual([{ sessionId, reason: 'device_mismatch' }]);
    expect(auditedActions(harness.audit)).toContain('auth.refresh.device_mismatch');
  });

  it('accepts a cookie without a device key', async () => {
    const { harness, refreshToken } = await registered();

    const credentials = issued(
      await harness.service.refresh(cookieContext(refreshToken, { deviceKey: null })),
    );

    expect(credentials.refreshToken).not.toBe(refreshToken);
  });

  it('refuses a blocked account and revokes the session', async () => {
    const { harness, refreshToken, sessionId } = await registered();
    const user = [...harness.sessions.users.values()][0];

    if (user !== undefined) user.status = 'BLOCKED';

    await expect(harness.service.refresh(cookieContext(refreshToken))).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect(harness.sessions.revokedSessions).toEqual([{ sessionId, reason: 'account_blocked' }]);
    expect(auditedActions(harness.audit)).toContain('auth.refresh.blocked');
  });

  it('answers 401 once the absolute session lifetime has passed', async () => {
    const { harness, refreshToken } = await registered();

    jest.setSystemTime(new Date(TEST_NOW.getTime() + 31 * SECONDS_PER_DAY * 1_000));

    await expect(harness.service.refresh(cookieContext(refreshToken))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('throttles by IP before reading the cookie', async () => {
    const { harness, refreshToken } = await registered();
    harness.rateLimit.seed(
      'refresh-ip',
      TEST_CONTEXT.ip,
      REFRESH_IP_LIMIT.limit,
      REFRESH_IP_LIMIT.windowSeconds,
    );

    expect(throttled(await harness.service.refresh(cookieContext(refreshToken)))).toBe(
      REFRESH_IP_LIMIT.windowSeconds,
    );
    expect(harness.sessions.refreshTokens.get(hashRefreshToken(refreshToken))?.usedAt).toBeNull();
  });
});

describe('AuthService.logout', () => {
  it('revokes the session behind the cookie', async () => {
    const { harness, refreshToken, sessionId } = await registered();

    expect(await harness.service.logout(cookieContext(refreshToken))).toEqual({ outcome: 'ok' });

    expect(harness.sessions.revokedSessions).toEqual([{ sessionId, reason: 'logout' }]);
    expect(auditedActions(harness.audit)).toContain('auth.logout');
    await expect(harness.service.refresh(cookieContext(refreshToken))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('succeeds for missing, malformed and unknown cookies', async () => {
    const { harness } = await registered();

    expect(await harness.service.logout(TEST_CONTEXT)).toEqual({ outcome: 'ok' });
    expect(
      await harness.service.logout(contextWith({ cookieHeader: `${REFRESH_COOKIE_NAME}=nope` })),
    ).toEqual({ outcome: 'ok' });
    expect(await harness.service.logout(cookieContext(generateRefreshToken()))).toEqual({
      outcome: 'ok',
    });
    expect(harness.sessions.revokedSessions).toHaveLength(0);
  });

  it('throttles by IP without touching the session', async () => {
    const { harness, refreshToken } = await registered();
    harness.rateLimit.seed(
      'logout-ip',
      TEST_CONTEXT.ip,
      LOGOUT_IP_LIMIT.limit,
      LOGOUT_IP_LIMIT.windowSeconds,
    );

    expect(throttled(await harness.service.logout(cookieContext(refreshToken)))).toBe(
      LOGOUT_IP_LIMIT.windowSeconds,
    );
    expect(harness.sessions.revokedSessions).toHaveLength(0);
  });
});
