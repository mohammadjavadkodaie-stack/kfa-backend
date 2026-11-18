import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { PasswordService } from '../src/auth/password/password.service';
import { REFRESH_COOKIE_NAME, hashRefreshToken } from '../src/auth/token/refresh-token';
import type { RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';
import {
  TEST_ACCOUNT_PASSWORD,
  issueEmailProof,
  signInByEmail,
  signUpByEmail,
} from './helpers/email-account';
import { InMemoryProofNonceStore } from './helpers/proof-nonce-store';

/**
 * Session lifecycle over HTTP, with every external dependency replaced:
 * the sessions live in memory, email proofs are minted in-process and the
 * explicit limiter always allows. What is left under test is the contract
 * itself - status codes, the cookie and the fact that the JSON body never
 * carries the refresh token.
 */

const EMAIL = 'ivan@example.com';
const UNKNOWN_EMAIL = 'nobody@example.com';
const USERNAME = 'ivan';

/** Fixed decision, so a test can exhaust a budget without hitting a store. */
function rateLimitStub(allowed: boolean, retryAfterSeconds = 42): RateLimitService {
  const decision = { allowed, remaining: allowed ? 99 : 0, retryAfterSeconds };

  return {
    consume: (): Promise<typeof decision> => Promise.resolve(decision),
    peek: (): Promise<typeof decision> => Promise.resolve(decision),
    reset: (): Promise<void> => Promise.resolve(),
  } as unknown as RateLimitService;
}

function setCookies(response: request.Response): string[] {
  const header: unknown = response.headers['set-cookie'];

  if (Array.isArray(header)) return header as string[];

  return typeof header === 'string' ? [header] : [];
}

/** The `name=value` pair of the refresh cookie, ready to be sent back. */
function refreshCookie(response: request.Response): string | null {
  for (const cookie of setCookies(response)) {
    const pair = cookie.split(';')[0] ?? '';

    if (pair.startsWith(`${REFRESH_COOKIE_NAME}=`)) return pair;
  }

  return null;
}

function refreshCookieAttributes(response: request.Response): string | null {
  return (
    setCookies(response).find((cookie) => cookie.startsWith(`${REFRESH_COOKIE_NAME}=`)) ?? null
  );
}

function refreshTokenOf(response: request.Response): string {
  const pair = refreshCookie(response);

  if (pair === null) throw new Error('no refresh cookie in the response');

  return pair.slice(REFRESH_COOKIE_NAME.length + 1);
}

const GENERIC_UNAUTHORIZED = { error: 'invalid_credentials' };

describe('Auth HTTP contract (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let nonces: InMemoryProofNonceStore;

  const server = () => request(app.getHttpServer());

  const register = async (username: string = USERNAME, email: string = EMAIL) =>
    signUpByEmail(app, { email, username });

  /** Same, but the caller expects a 200: keeps the assertions readable. */
  const registerOk = async (username: string = USERNAME, email: string = EMAIL) => {
    const response = await register(username, email);

    expect(response.status).toBe(200);

    return response;
  };

  const login = async (email: string = EMAIL, username: string = USERNAME) =>
    signInByEmail(app, { email, username });

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    nonces = new InMemoryProofNonceStore();
    app = await createTestApp(
      {},
      { sessionRepository: sessions, proofNonceStore: nonces, rateLimit: rateLimitStub(true) },
    );
  });

  beforeEach(() => {
    sessions.users.clear();
    sessions.sessions.clear();
    sessions.refreshTokens.clear();
    sessions.revokedSessions.length = 0;
    nonces.clear();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /auth/signup', () => {
    it('creates the account, sets the cookie and returns only the access token', async () => {
      const response = await register();

      expect(response.status).toBe(200);
      expect(Object.keys(response.body)).toEqual(['accessToken', 'tokenType', 'expiresIn']);
      expect(response.body).toMatchObject({ tokenType: 'Bearer', expiresIn: 600 });

      const cookie = refreshCookieAttributes(response);
      expect(cookie).toContain(`; HttpOnly`);
      expect(cookie).toContain('; Secure');
      expect(cookie).toContain('; SameSite=Strict');
      expect(cookie).toContain('; Path=/');
      expect(cookie).toContain('; Max-Age=1209600');
      expect(refreshTokenOf(response)).toHaveLength(43);

      // The token is never echoed in the body...
      expect(response.text).not.toContain(refreshTokenOf(response));
      // ...and only its hash is stored.
      expect(sessions.refreshTokens.has(hashRefreshToken(refreshTokenOf(response)))).toBe(true);

      // The access token is accepted by the default-deny guard.
      await server()
        .get('/test/protected')
        .set('Authorization', `Bearer ${response.body.accessToken as string}`)
        .expect(200);
    });

    it('answers 409 for an email that already has an account', async () => {
      await registerOk();

      const response = await register('other_name', EMAIL);

      expect(response.status).toBe(409);
      expect(response.body).toEqual({ error: 'unavailable' });
      expect(refreshCookie(response)).toBeNull();
    });

    it('answers 409 for a username that only differs in case', async () => {
      await registerOk();

      const response = await register('IVAN', UNKNOWN_EMAIL);

      expect(response.status).toBe(409);
      expect(response.body).toEqual({ error: 'unavailable' });
    });

    it('rejects an unexpected field with the generic envelope', async () => {
      const response = await server()
        .post('/auth/signup')
        .send({
          proof: await issueEmailProof(app, EMAIL, 'register'),
          username: USERNAME,
          password: TEST_ACCOUNT_PASSWORD,
          isAdmin: true,
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        statusCode: 400,
        message: 'Bad Request',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain('isAdmin');
    });

    it('answers 401 for a proof that does not verify', async () => {
      const response = await server()
        .post('/auth/signup')
        .send({ proof: 'not-a-proof', username: USERNAME, password: TEST_ACCOUNT_PASSWORD });

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(refreshCookie(response)).toBeNull();
    });
  });

  describe('POST /auth/signin', () => {
    it('opens a second session for an existing account', async () => {
      const first = await registerOk();
      const response = await login();

      expect(response.status).toBe(200);
      expect(Object.keys(response.body)).toEqual(['accessToken', 'tokenType', 'expiresIn']);
      expect(refreshTokenOf(response)).not.toBe(refreshTokenOf(first));
      expect(sessions.sessions.size).toBe(2);
    });

    it('answers the same 401 for an unknown email and a stale proof', async () => {
      const unknownEmail = await login(UNKNOWN_EMAIL);
      const staleProof = await server().post('/auth/signin').send({
        email: EMAIL,
        password: TEST_ACCOUNT_PASSWORD,
        proof: 'not-a-proof',
      });

      expect(unknownEmail.status).toBe(401);
      expect(staleProof.status).toBe(401);
      expect(unknownEmail.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(staleProof.body).toEqual(unknownEmail.body);
    });

    it('refuses a proof minted for another action', async () => {
      await registerOk();

      // A register proof cannot be replayed as a signin, and vice versa.
      const registerAsLogin = await server()
        .post('/auth/signin')
        .send({
          email: EMAIL,
          password: TEST_ACCOUNT_PASSWORD,
          proof: await issueEmailProof(app, EMAIL, 'register'),
        });
      const loginAsRegister = await server()
        .post('/auth/signup')
        .send({
          proof: await issueEmailProof(app, UNKNOWN_EMAIL, 'login_device'),
          username: 'other_name',
          password: TEST_ACCOUNT_PASSWORD,
        });

      expect(registerAsLogin.status).toBe(401);
      expect(registerAsLogin.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(refreshCookie(registerAsLogin)).toBeNull();
      expect(loginAsRegister.status).toBe(401);
      expect(loginAsRegister.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(refreshCookie(loginAsRegister)).toBeNull();
      // Neither attempt created a session or an account.
      expect(sessions.sessions.size).toBe(1);
      expect(sessions.users.size).toBe(1);
    });

    it('answers 401 - not 403 - for a blocked account', async () => {
      sessions.seedUser({
        phone: null,
        email: EMAIL,
        passwordHash: await app.get(PasswordService).hash(TEST_ACCOUNT_PASSWORD),
        username: USERNAME,
        status: 'BLOCKED',
      });

      const response = await login();

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(refreshCookie(response)).toBeNull();
    });
  });

  describe('POST /auth/refresh', () => {
    it('rotates the cookie and revokes everything when the old one comes back', async () => {
      const registered = await registerOk();
      const original = refreshTokenOf(registered);

      const rotated = await server()
        .post('/auth/refresh')
        .set('Cookie', `${REFRESH_COOKIE_NAME}=${original}`);

      expect(rotated.status).toBe(200);
      expect(Object.keys(rotated.body)).toEqual(['accessToken', 'tokenType', 'expiresIn']);
      expect(refreshTokenOf(rotated)).not.toBe(original);

      // Replaying the spent cookie is treated as theft.
      const replayed = await server()
        .post('/auth/refresh')
        .set('Cookie', `${REFRESH_COOKIE_NAME}=${original}`);

      expect(replayed.status).toBe(401);
      expect(replayed.body).toEqual(GENERIC_UNAUTHORIZED);
      expect(refreshCookieAttributes(replayed)).toContain('; Expires=');

      // The winner of the race is logged out too: the session is now revoked.
      const afterReuse = await server()
        .post('/auth/refresh')
        .set('Cookie', `${REFRESH_COOKIE_NAME}=${refreshTokenOf(rotated)}`);

      expect(afterReuse.status).toBe(401);
      expect(sessions.revokedSessions).toEqual([
        { sessionId: expect.any(String), reason: 'refresh_reuse' },
      ]);
    });

    it('answers 401 and clears the cookie when there is nothing to rotate', async () => {
      const response = await server().post('/auth/refresh');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);

      const cleared = refreshCookieAttributes(response);
      expect(cleared).toContain(`${REFRESH_COOKIE_NAME}=;`);
      expect(cleared).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    });
  });

  describe('POST /auth/logout', () => {
    it('answers 204, clears the cookie and revokes the session', async () => {
      const registered = await registerOk();
      const cookie = refreshCookie(registered) ?? '';

      const response = await server().post('/auth/logout').set('Cookie', cookie);

      expect(response.status).toBe(204);
      expect(response.text).toBe('');
      expect(refreshCookieAttributes(response)).toContain(`${REFRESH_COOKIE_NAME}=;`);
      expect(sessions.revokedSessions).toEqual([
        { sessionId: expect.any(String), reason: 'logout' },
      ]);

      // Neither credential works any more.
      await server()
        .get('/test/protected')
        .set('Authorization', `Bearer ${registered.body.accessToken as string}`)
        .expect(401);
      await server().post('/auth/refresh').set('Cookie', cookie).expect(401);
    });

    it('answers 204 even without a usable cookie', async () => {
      const response = await server().post('/auth/logout');

      expect(response.status).toBe(204);
      expect(sessions.revokedSessions).toHaveLength(0);
    });
  });

  describe('Origin checks', () => {
    it('rejects a non-allowlisted origin on the cookie endpoints', async () => {
      const response = await server().post('/auth/refresh').set('Origin', 'https://evil.example');

      expect(response.status).toBe(403);
      expect(response.body).toEqual({
        statusCode: 403,
        message: 'Forbidden',
        requestId: expect.any(String) as string,
      });
    });

    it('rejects a cross-site fetch without an Origin header', async () => {
      await server()
        .post('/auth/signup')
        .set('Sec-Fetch-Site', 'cross-site')
        .send({ proof: await issueEmailProof(app, EMAIL, 'register'), username: USERNAME })
        .expect(403);
    });
  });
});

describe('Auth rate limiting (e2e)', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApp(
      {},
      {
        sessionRepository: new InMemorySessionRepository(),
        proofNonceStore: new InMemoryProofNonceStore(),
        rateLimit: rateLimitStub(false, 42),
      },
    );
  });

  afterAll(async () => {
    await app.close();
  });

  const server = () => request(app.getHttpServer());

  it('answers 429 with Retry-After for every endpoint', async () => {
    const responses = [
      await server().post('/auth/signup').send({
        proof: 'proof',
        username: USERNAME,
        password: TEST_ACCOUNT_PASSWORD,
      }),
      await server()
        .post('/auth/signin')
        .send({ email: EMAIL, password: TEST_ACCOUNT_PASSWORD, proof: 'proof' }),
      await server().post('/auth/refresh'),
      await server().post('/auth/logout'),
    ];

    for (const response of responses) {
      expect(response.status).toBe(429);
      expect(response.headers['retry-after']).toBe('42');
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain('proof');
    }
  });
});
