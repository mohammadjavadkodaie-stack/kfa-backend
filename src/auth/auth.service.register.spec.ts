import {
  BadRequestException,
  ConflictException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  REGISTER_BODY,
  TEST_CONTEXT,
  TEST_NOW,
  TEST_OTHER_PHONE,
  TEST_PHONE,
  TEST_SECRET,
  TEST_USERNAME,
  auditedActions,
  auditedMetadata,
  createHarness,
  issued,
  throttled,
} from '../../test/helpers/auth-service-harness';
import { REGISTER_IP_LIMIT } from './auth.service';
import { hashDeviceKey } from './device-key';
import { maskPhone } from './phone';
import { verifyAccessToken } from './token/access-token';
import { hashRefreshToken } from './token/refresh-token';

const SECONDS_PER_DAY = 86_400;

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AuthService.register', () => {
  it('creates the account, its device and the first session together', async () => {
    const harness = createHarness();

    const credentials = issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT));
    const user = [...harness.sessions.users.values()][0];
    const session = [...harness.sessions.sessions.values()][0];

    expect(harness.sessions.users.size).toBe(1);
    expect(harness.sessions.sessions.size).toBe(1);
    expect(user?.phone).toBe(TEST_PHONE);
    expect(user?.username).toBe(TEST_USERNAME);
    expect(credentials.userId).toBe(user?.id);
    expect(credentials.sessionId).toBe(session?.id);
    expect(session?.deviceKeyHash).toBe(hashDeviceKey(TEST_SECRET, user?.id ?? '', 'device-1'));
    expect(session?.expiresAt).toEqual(new Date(TEST_NOW.getTime() + 30 * SECONDS_PER_DAY * 1_000));
  });

  it('signs an access token for the new session and only stores the refresh hash', async () => {
    const harness = createHarness();

    const credentials = issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT));
    const claims = verifyAccessToken({
      secret: TEST_SECRET,
      token: credentials.accessToken,
      nowSeconds: Math.floor(TEST_NOW.getTime() / 1_000),
    });

    expect(claims?.sub).toBe(credentials.userId);
    expect(claims?.sid).toBe(credentials.sessionId);
    expect(credentials.tokenType).toBe('Bearer');
    expect(credentials.expiresIn).toBe(600);
    expect(credentials.expiresAt).toBe('2026-03-01T00:10:00.000Z');
    expect([...harness.sessions.refreshTokens.keys()]).toEqual([
      hashRefreshToken(credentials.refreshToken),
    ]);
    // The raw token must never reach storage.
    expect(harness.sessions.refreshTokens.has(credentials.refreshToken)).toBe(false);
  });

  it('caps the cookie lifetime by the absolute session lifetime', async () => {
    const harness = createHarness({ sessionAbsoluteDays: 1 });

    const credentials = issued(await harness.service.register(REGISTER_BODY, TEST_CONTEXT));

    expect(credentials.refreshMaxAgeSeconds).toBe(SECONDS_PER_DAY);
  });

  it('prefers an explicit device name over the user agent', async () => {
    const harness = createHarness();
    const createAccount = jest.spyOn(harness.sessions, 'createAccount');

    await harness.service.register({ ...REGISTER_BODY, deviceName: 'Ivan iPhone' }, TEST_CONTEXT);

    expect(createAccount.mock.calls[0]?.[0].deviceLabel).toBe('Ivan iPhone');
  });

  it('falls back to a truncated user agent when no name is sent', async () => {
    const harness = createHarness();
    const createAccount = jest.spyOn(harness.sessions, 'createAccount');

    await harness.service.register(REGISTER_BODY, {
      ...TEST_CONTEXT,
      userAgent: 'u'.repeat(200),
    });

    expect(createAccount.mock.calls[0]?.[0].deviceLabel).toBe('u'.repeat(100));
  });

  it('answers 401 for a proof that no longer resolves and stores nothing', async () => {
    const harness = createHarness();
    harness.proof.phone = null;

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    expect(harness.sessions.users.size).toBe(0);
    expect(harness.sessions.sessions.size).toBe(0);
  });

  it('refuses a phone that already has an account', async () => {
    const harness = createHarness();
    harness.sessions.seedUser({ phone: TEST_PHONE, username: 'someone-else' });

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('refuses a username that is taken in a different case', async () => {
    const harness = createHarness();
    harness.sessions.seedUser({ phone: TEST_OTHER_PHONE, username: 'Ivan' });

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('rejects unknown fields and a missing username before spending the proof', async () => {
    const harness = createHarness();

    await expect(
      harness.service.register({ ...REGISTER_BODY, isAdmin: true }, TEST_CONTEXT),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      harness.service.register({ proof: 'proof-1' }, TEST_CONTEXT),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(harness.proof.consumed).toHaveLength(0);
  });

  it('throttles by IP before the proof or the database is touched', async () => {
    const harness = createHarness();
    harness.rateLimit.seed(
      'register-ip',
      TEST_CONTEXT.ip,
      REGISTER_IP_LIMIT.limit,
      REGISTER_IP_LIMIT.windowSeconds,
    );

    const result = await harness.service.register(REGISTER_BODY, TEST_CONTEXT);

    expect(throttled(result)).toBe(REGISTER_IP_LIMIT.windowSeconds);
    expect(harness.proof.consumed).toHaveLength(0);
    expect(harness.sessions.users.size).toBe(0);
  });

  it('maps a lost race on the unique constraints to 409', async () => {
    const harness = createHarness();
    jest.spyOn(harness.sessions, 'createAccount').mockResolvedValue(null);

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('fails closed when no signing secret is configured', async () => {
    const harness = createHarness({ ACCESS_TOKEN_SECRET: undefined });

    await expect(harness.service.register(REGISTER_BODY, TEST_CONTEXT)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('audits the registration with a masked phone and no raw number', async () => {
    const harness = createHarness();

    await harness.service.register(REGISTER_BODY, TEST_CONTEXT);

    expect(auditedActions(harness.audit)).toEqual(['auth.registered']);
    expect(auditedMetadata(harness.audit, 'auth.registered')).toMatchObject({
      actor: 'user',
      phone: maskPhone(TEST_PHONE),
      username: TEST_USERNAME,
    });
    expect(JSON.stringify(harness.audit.records)).not.toContain(TEST_PHONE);
  });
});
