import { ServiceUnavailableException } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { AuthService, ME_USER_LIMIT } from '../src/auth/auth.service';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { REFRESH_COOKIE_NAME } from '../src/auth/token/refresh-token';
import { SECOND_FACTOR_REQUIRED_CODE } from '../src/common/errors/error-response';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * `GET /auth/me` over HTTP with no database, no Redis and no SMS provider: the
 * store is in memory, proofs are minted in-process and the explicit limiter is
 * a switch that also records what it was asked for.
 *
 * The contract under test is narrow on purpose - the four keys and nothing
 * else, the Bearer-only credential, the staff-without-TOTP exception and the
 * generic refusals.
 */

const PHONE = '+14155552671';
const OTHER_PHONE = '+14155550123';
const USERNAME = 'ivan';

/** Nonce store stand-in: `ProofTokenService` keeps its real signing logic. */
class InMemoryNonceStore implements ProofNonceStore {
  private readonly nonces = new Map<string, { phone: string; expiresAt: number }>();

  async put(jti: string, phoneE164: string, ttlSeconds: number): Promise<boolean> {
    this.nonces.set(jti, { phone: phoneE164, expiresAt: Date.now() + ttlSeconds * 1_000 });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const stored = this.nonces.get(jti);
    this.nonces.delete(jti);

    return stored === undefined || stored.expiresAt <= Date.now() ? null : stored.phone;
  }
}

/**
 * The explicit limiter, with a switch and a log of every request: one app
 * instance can admit a registration, then refuse everything, then behave as if
 * Redis were down.
 */
class SwitchableRateLimit {
  allowed = true;
  storeDown = false;
  readonly retryAfterSeconds = 17;
  readonly calls: ConsumeRateLimitInput[] = [];

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    this.calls.push(input);

    if (this.storeDown) throw new ServiceUnavailableException();

    return {
      allowed: this.allowed,
      remaining: this.allowed ? 99 : 0,
      retryAfterSeconds: this.allowed ? 0 : this.retryAfterSeconds,
    };
  }

  async reset(): Promise<void> {
    this.allowed = true;
  }
}

const bearer = (accessToken: string): Record<string, string> => ({
  Authorization: `Bearer ${accessToken}`,
});

const GENERIC_UNAUTHORIZED = {
  statusCode: 401,
  message: 'Unauthorized',
  requestId: expect.any(String) as string,
};

const GENERIC_UNAVAILABLE = {
  statusCode: 503,
  message: 'Service Unavailable',
  requestId: expect.any(String) as string,
};

const GENERIC_TOO_MANY = {
  statusCode: 429,
  message: 'Too Many Requests',
  requestId: expect.any(String) as string,
};

const ME_KEYS = ['hasAthleteProfile', 'role', 'status', 'username'];

/** The first `Set-Cookie` value that carries the refresh token, if any. */
function refreshCookieOf(response: request.Response): string {
  const header: unknown = response.headers['set-cookie'];
  const cookies = Array.isArray(header) ? header : typeof header === 'string' ? [header] : [];
  const cookie = cookies.find((value) => value.startsWith(`${REFRESH_COOKIE_NAME}=`));

  if (cookie === undefined) throw new Error('no refresh cookie in the response');

  return cookie.split(';')[0] ?? '';
}

describe('GET /auth/me (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let limiter: SwitchableRateLimit;

  const server = () => request(app.getHttpServer());

  const registerOk = async (username: string = USERNAME, phone: string = PHONE) => {
    const response = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

    expect(response.status).toBe(200);

    return response;
  };

  const accessTokenOf = (response: request.Response): string =>
    (response.body as { accessToken: string }).accessToken;

  const me = (accessToken: string) => server().get('/auth/me').set(bearer(accessToken));

  /** The account the last registration created; ids are opaque to the client. */
  const onlyUserId = (): string => {
    const [id] = [...sessions.users.keys()];

    if (id === undefined) throw new Error('no account was registered');

    return id;
  };

  const userIdOfPhone = (phone: string): string => {
    for (const [id, user] of sessions.users) {
      if (user.phone === phone) return id;
    }

    throw new Error(`no account owns ${phone}`);
  };

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    limiter = new SwitchableRateLimit();
    app = await createTestApp(
      {},
      {
        sessionRepository: sessions,
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: limiter as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  beforeEach(() => {
    sessions.users.clear();
    sessions.sessions.clear();
    sessions.refreshTokens.clear();
    sessions.athleteProfiles.clear();
    sessions.revokedSessions.length = 0;
    limiter.allowed = true;
    limiter.storeDown = false;
    limiter.calls.length = 0;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('access control', () => {
    it('refuses a request without a bearer token', async () => {
      const response = await server().get('/auth/me');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
    });

    it('does not accept the refresh cookie as a credential', async () => {
      const registered = await registerOk();
      const response = await server().get('/auth/me').set('Cookie', refreshCookieOf(registered));

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
    });

    it('refuses an account blocked after it signed in', async () => {
      const registered = await registerOk();

      await sessions.setStatusIf(onlyUserId(), 'ACTIVE', 'BLOCKED');

      const response = await me(accessTokenOf(registered));

      // Indistinguishable from a token that was never valid.
      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
    });

    it('fails closed when the limiter store is down', async () => {
      const registered = await registerOk();
      limiter.storeDown = true;

      const response = await me(accessTokenOf(registered));

      expect(response.status).toBe(503);
      expect(response.body).toEqual(GENERIC_UNAVAILABLE);
    });
  });

  describe('the response', () => {
    it('carries exactly the four keys and nothing else', async () => {
      const registered = await registerOk();
      const response = await me(accessTokenOf(registered));

      expect(response.status).toBe(200);
      expect(Object.keys(response.body as object).sort()).toEqual(ME_KEYS);
      expect(response.body).toEqual({
        username: USERNAME,
        role: 'USER',
        status: 'ACTIVE',
        hasAthleteProfile: false,
      });
    });

    it('never contains the phone, an id or the token', async () => {
      const registered = await registerOk();
      const token = accessTokenOf(registered);
      const response = await me(token);

      expect(response.status).toBe(200);
      expect(response.text).not.toContain(PHONE);
      expect(response.text).not.toContain(onlyUserId());
      expect(response.text).not.toContain(token);
    });

    it('reflects the role and the profile flag of the caller', async () => {
      const registered = await registerOk();
      const token = accessTokenOf(registered);

      sessions.setUserRole(onlyUserId(), { role: Role.ATHLETE });

      const withoutProfile = await me(token);

      expect(withoutProfile.status).toBe(200);
      expect(withoutProfile.body).toEqual({
        username: USERNAME,
        role: 'ATHLETE',
        status: 'ACTIVE',
        hasAthleteProfile: false,
      });

      sessions.seedAthleteProfile(onlyUserId());

      const withProfile = await me(token);

      expect(withProfile.status).toBe(200);
      expect(withProfile.body).toEqual({
        username: USERNAME,
        role: 'ATHLETE',
        status: 'ACTIVE',
        hasAthleteProfile: true,
      });
    });

    it('ignores a user id in the query string', async () => {
      const mine = await registerOk();
      await registerOk('other_user', OTHER_PHONE);
      const foreignId = userIdOfPhone(OTHER_PHONE);

      const response = await server()
        .get(`/auth/me?userId=${foreignId}`)
        .set(bearer(accessTokenOf(mine)));

      expect(response.status).toBe(200);
      expect((response.body as { username: string }).username).toBe(USERNAME);
    });

    it('is never cacheable, refusals included', async () => {
      const registered = await registerOk();
      const ok = await me(accessTokenOf(registered));
      const refused = await server().get('/auth/me');

      expect(ok.headers['cache-control']).toBe('no-store');
      expect(refused.headers['cache-control']).toBe('no-store');
    });
  });

  describe('second factor', () => {
    it('answers a staff session that has not proved TOTP', async () => {
      const registered = await registerOk();
      const token = accessTokenOf(registered);

      sessions.setUserRole(onlyUserId(), { role: Role.ADMIN });

      const response = await me(token);

      expect(response.status).toBe(200);
      expect((response.body as { role: string }).role).toBe('ADMIN');

      // The control case: the same unproven session is still gated elsewhere,
      // so the exception belongs to this route and not to the gate.
      const gated = await server().get('/auth/sessions').set(bearer(token));

      expect(gated.status).toBe(403);
      expect((gated.body as { code?: string }).code).toBe(SECOND_FACTOR_REQUIRED_CODE);
    });
  });

  describe('rate limit', () => {
    it('asks for 60 requests per minute per user and then answers 429', async () => {
      const registered = await registerOk();
      const token = accessTokenOf(registered);
      const userId = onlyUserId();

      expect(ME_USER_LIMIT).toEqual({ limit: 60, windowSeconds: 60 });

      const admitted = await me(token);

      expect(admitted.status).toBe(200);

      limiter.allowed = false;

      const refused = await me(token);

      expect(refused.status).toBe(429);
      expect(refused.body).toEqual(GENERIC_TOO_MANY);
      expect(refused.headers['retry-after']).toBe(String(limiter.retryAfterSeconds));

      // The bucket is the caller's user id, with this route's budget.
      const meCalls = limiter.calls.filter((call) => call.identifier === userId);

      expect(meCalls).toHaveLength(2);
      expect(meCalls[0]).toMatchObject({ limit: 60, windowSeconds: 60 });
      expect(meCalls[1]).toMatchObject({ limit: 60, windowSeconds: 60 });
    });
  });

  describe('service contract', () => {
    it('treats a blocked or vanished account as unauthenticated', async () => {
      const registered = await registerOk();
      const userId = onlyUserId();
      const service = app.get(AuthService);

      expect(registered.status).toBe(200);

      await sessions.setStatusIf(userId, 'ACTIVE', 'BLOCKED');

      expect(await service.getMe({ userId, sessionId: 'current' })).toEqual({
        outcome: 'unauthorized',
      });

      sessions.users.delete(userId);

      expect(await service.getMe({ userId, sessionId: 'current' })).toEqual({
        outcome: 'unauthorized',
      });
    });
  });
});
