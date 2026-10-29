import { UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import type { ActiveSessionRecord, SessionRepository } from '../session.repository';
import { Role } from '../roles';
import { signAccessToken } from '../token/access-token';
import { AuthGuard, readBearerToken, type AuthenticatedRequest } from './auth.guard';

const SECRET = 'unit-test-access-token-secret-0123456789abcdef';
const OTHER_SECRET = 'another-access-token-secret-0123456789abcdef';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';

const handler = (): void => undefined;
class TestController {}

function accessToken(overrides: { ttlSeconds?: number; secret?: string } = {}): string {
  return signAccessToken({
    secret: overrides.secret ?? SECRET,
    userId: USER_ID,
    sessionId: SESSION_ID,
    issuedAtSeconds: Math.floor(Date.now() / 1_000),
    ttlSeconds: overrides.ttlSeconds ?? 600,
  });
}

interface Harness {
  readonly guard: AuthGuard;
  readonly context: ExecutionContext;
  readonly request: AuthenticatedRequest;
  readonly findActiveSession: jest.Mock;
  readonly getAllAndOverride: jest.Mock;
}

/** What the repository returns for a live session. */
function activeSession(overrides: Partial<ActiveSessionRecord> = {}): ActiveSessionRecord {
  return {
    sessionId: SESSION_ID,
    userId: USER_ID,
    role: Role.USER,
    identityVerifier: false,
    status: 'ACTIVE',
    ...overrides,
  };
}

function createHarness(options: {
  isPublic?: boolean;
  authorization?: string;
  secret?: string;
  /** Defaults to a live session; pass `null` for a revoked or unknown one. */
  session?: ActiveSessionRecord | null;
}): Harness {
  const request = { headers: {} } as unknown as AuthenticatedRequest;

  if (options.authorization !== undefined) {
    request.headers.authorization = options.authorization;
  }

  const context = {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;

  const getAllAndOverride = jest.fn().mockReturnValue(options.isPublic);
  const findActiveSession = jest
    .fn()
    .mockResolvedValue(options.session === undefined ? activeSession() : options.session);
  const sessions = { findActiveSession } as unknown as SessionRepository;

  const guard = new AuthGuard(
    { getAllAndOverride } as unknown as Reflector,
    { ACCESS_TOKEN_SECRET: options.secret },
    sessions,
  );

  return { guard, context, request, findActiveSession, getAllAndOverride };
}

describe('readBearerToken', () => {
  it.each([
    ['a standard header', 'Bearer token', 'token'],
    ['a lowercase scheme', 'bearer token', 'token'],
    ['extra spaces', 'Bearer    token', 'token'],
  ])('parses %s', (_label, header, expected) => {
    expect(readBearerToken(header)).toBe(expected);
  });

  it.each([
    ['a missing header', undefined],
    ['an empty header', ''],
    ['a basic header', 'Basic dXNlcjpwYXNz'],
    ['a bare token', 'token'],
    ['a scheme without a value', 'Bearer'],
    ['a token with a space', 'Bearer a b'],
  ])('returns null for %s', (_label, header) => {
    expect(readBearerToken(header)).toBeNull();
  });

  it('uses the first value of a repeated header', () => {
    expect(readBearerToken(['Bearer one', 'Bearer two'])).toBe('one');
  });
});

describe('AuthGuard', () => {
  it('allows routes marked with @Public() without a token', async () => {
    const harness = createHarness({ isPublic: true });

    await expect(harness.guard.canActivate(harness.context)).resolves.toBe(true);
    expect(harness.findActiveSession).not.toHaveBeenCalled();
  });

  it('denies a protected route without an Authorization header', async () => {
    const harness = createHarness({});

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.findActiveSession).not.toHaveBeenCalled();
  });

  it('reads the metadata from both the handler and the controller', async () => {
    const harness = createHarness({ secret: SECRET, authorization: `Bearer ${accessToken()}` });

    await expect(harness.guard.canActivate(harness.context)).resolves.toBe(true);
    expect(harness.getAllAndOverride).toHaveBeenCalledWith(IS_PUBLIC_KEY, [
      handler,
      TestController,
    ]);
  });

  it('denies a request when no signing secret is configured', async () => {
    const harness = createHarness({ authorization: `Bearer ${accessToken()}` });

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.findActiveSession).not.toHaveBeenCalled();
  });

  it('denies a token signed with another secret', async () => {
    const harness = createHarness({
      secret: SECRET,
      authorization: `Bearer ${accessToken({ secret: OTHER_SECRET })}`,
    });

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.findActiveSession).not.toHaveBeenCalled();
  });

  it('denies an expired token', async () => {
    const harness = createHarness({
      secret: SECRET,
      authorization: `Bearer ${accessToken({ ttlSeconds: -10 })}`,
    });

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.findActiveSession).not.toHaveBeenCalled();
  });

  it('accepts a valid token for a live session and exposes the principal', async () => {
    const harness = createHarness({ secret: SECRET, authorization: `Bearer ${accessToken()}` });

    await expect(harness.guard.canActivate(harness.context)).resolves.toBe(true);
    expect(harness.findActiveSession).toHaveBeenCalledWith(SESSION_ID, USER_ID, expect.any(Date));
    expect(harness.request.auth).toEqual({
      userId: USER_ID,
      sessionId: SESSION_ID,
      role: Role.USER,
      identityVerifier: false,
      expiresAtSeconds: expect.any(Number),
    });
  });

  it('takes the role and the verifier flag from the lookup, never from the token', async () => {
    const harness = createHarness({
      secret: SECRET,
      authorization: `Bearer ${accessToken()}`,
      session: activeSession({ role: Role.OWNER, identityVerifier: true }),
    });

    await expect(harness.guard.canActivate(harness.context)).resolves.toBe(true);
    expect(harness.request.auth).toMatchObject({ role: Role.OWNER, identityVerifier: true });
  });

  it('denies a valid token whose session was revoked or expired', async () => {
    const harness = createHarness({
      secret: SECRET,
      authorization: `Bearer ${accessToken()}`,
      session: null,
    });

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.request.auth).toBeUndefined();
  });

  it('denies a valid token when the account behind the session is blocked', async () => {
    const harness = createHarness({
      secret: SECRET,
      authorization: `Bearer ${accessToken()}`,
      session: activeSession({ status: 'BLOCKED' }),
    });

    await expect(harness.guard.canActivate(harness.context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(harness.request.auth).toBeUndefined();
  });
});
