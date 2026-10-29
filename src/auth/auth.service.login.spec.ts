import { BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import {
  LOGIN_BODY,
  TEST_CONTEXT,
  TEST_NOW,
  TEST_OTHER_PHONE,
  TEST_PHONE,
  TEST_SECRET,
  TEST_USERNAME,
  auditedActions,
  auditedMetadata,
  contextWith,
  createHarness,
  issued,
  throttled,
} from '../../test/helpers/auth-service-harness';
import { LOGIN_DEVICE_LIMIT, LOGIN_IP_LIMIT } from './auth.service';
import { hashDeviceKey } from './device-key';
import { maskPhone } from './phone';
import { verifyAccessToken } from './token/access-token';

const SECONDS_PER_DAY = 86_400;

function seedActiveUser(harness: ReturnType<typeof createHarness>): { id: string } {
  return harness.sessions.seedUser({ phone: TEST_PHONE, username: TEST_USERNAME });
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AuthService.login', () => {
  it('issues a session for an active account', async () => {
    const harness = createHarness();
    const user = seedActiveUser(harness);

    const credentials = issued(await harness.service.login(LOGIN_BODY, TEST_CONTEXT));
    const claims = verifyAccessToken({
      secret: TEST_SECRET,
      token: credentials.accessToken,
      nowSeconds: Math.floor(TEST_NOW.getTime() / 1_000),
    });

    expect(credentials.userId).toBe(user.id);
    expect(claims?.sid).toBe(credentials.sessionId);
    expect(harness.sessions.sessions.size).toBe(1);
    expect(credentials.refreshMaxAgeSeconds).toBe(14 * SECONDS_PER_DAY);
    // A login only creates a session; the identity is left untouched.
    expect(harness.sessions.users.size).toBe(1);
  });

  it('binds the session to the hashed device key and the user agent label', async () => {
    const harness = createHarness();
    const user = seedActiveUser(harness);
    const createSession = jest.spyOn(harness.sessions, 'createSession');

    await harness.service.login(LOGIN_BODY, TEST_CONTEXT);

    expect(createSession.mock.calls[0]?.[0].deviceKeyHash).toBe(
      hashDeviceKey(TEST_SECRET, user.id, 'device-1'),
    );
    expect(createSession.mock.calls[0]?.[0].deviceLabel).toBe('jest-agent');
  });

  it('uses a random binding when the client sends no device key', async () => {
    const harness = createHarness();
    const user = seedActiveUser(harness);
    const createSession = jest.spyOn(harness.sessions, 'createSession');

    await harness.service.login(LOGIN_BODY, contextWith({ deviceKey: null }));

    const hash = createSession.mock.calls[0]?.[0].deviceKeyHash ?? '';

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toBe(hashDeviceKey(TEST_SECRET, user.id, 'device-1'));
  });

  it('audits the login with a masked phone', async () => {
    const harness = createHarness();
    seedActiveUser(harness);

    await harness.service.login(LOGIN_BODY, TEST_CONTEXT);

    expect(auditedActions(harness.audit)).toEqual(['auth.login']);
    expect(auditedMetadata(harness.audit, 'auth.login')).toMatchObject({
      actor: 'user',
      phone: maskPhone(TEST_PHONE),
    });
    expect(JSON.stringify(harness.audit.records)).not.toContain(TEST_PHONE);
  });

  it('answers the generic 401 for a number without an account', async () => {
    const harness = createHarness();
    harness.proof.phone = TEST_OTHER_PHONE;

    await expect(harness.service.login(LOGIN_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.sessions.sessions.size).toBe(0);
  });

  it('answers 401 for a proof that does not resolve', async () => {
    const harness = createHarness();
    seedActiveUser(harness);
    harness.proof.phone = null;

    await expect(harness.service.login(LOGIN_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('refuses a blocked account with 403 and audits it', async () => {
    const harness = createHarness();
    harness.sessions.seedUser({ phone: TEST_PHONE, username: TEST_USERNAME, status: 'BLOCKED' });

    await expect(harness.service.login(LOGIN_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect(auditedActions(harness.audit)).toEqual(['auth.login.blocked']);
    expect(harness.sessions.sessions.size).toBe(0);
  });

  it('requires exactly a proof field', async () => {
    const harness = createHarness();
    seedActiveUser(harness);

    await expect(harness.service.login({}, TEST_CONTEXT)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(
      harness.service.login({ proof: 'proof-1', username: TEST_USERNAME }, TEST_CONTEXT),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(harness.proof.consumed).toHaveLength(0);
  });

  it('throttles by IP before looking at the proof', async () => {
    const harness = createHarness();
    seedActiveUser(harness);
    harness.rateLimit.seed(
      'login-ip',
      TEST_CONTEXT.ip,
      LOGIN_IP_LIMIT.limit,
      LOGIN_IP_LIMIT.windowSeconds,
    );

    expect(throttled(await harness.service.login(LOGIN_BODY, TEST_CONTEXT))).toBe(
      LOGIN_IP_LIMIT.windowSeconds,
    );
    expect(harness.proof.consumed).toHaveLength(0);
  });

  it('throttles by device key after the IP budget', async () => {
    const harness = createHarness();
    seedActiveUser(harness);
    harness.rateLimit.seed(
      'login-device',
      'device-1',
      LOGIN_DEVICE_LIMIT.limit,
      LOGIN_DEVICE_LIMIT.windowSeconds,
    );

    expect(throttled(await harness.service.login(LOGIN_BODY, TEST_CONTEXT))).toBe(
      LOGIN_DEVICE_LIMIT.windowSeconds,
    );
    expect(harness.rateLimit.scopes()).toEqual(['login-ip', 'login-device']);
  });

  it('skips the device budget when no device key is sent', async () => {
    const harness = createHarness();
    seedActiveUser(harness);

    issued(await harness.service.login(LOGIN_BODY, contextWith({ deviceKey: null })));

    expect(harness.rateLimit.scopes()).toEqual(['login-ip']);
  });
});
