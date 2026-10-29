import type { NestExpressApplication } from '@nestjs/platform-express';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { REFRESH_COOKIE_NAME } from '../src/auth/token/refresh-token';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * Session management over HTTP with no database, no Redis and no SMS provider:
 * the store is in memory, proofs are minted in-process and the explicit limiter
 * is a switch. Only the contract is under test - status codes, the shape of the
 * list, the cookie clearing and the fact that a session id never leaks anything.
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
 * The explicit limiter, with a switch: the same app instance can first admit a
 * real registration and then refuse everything, which is what a browser sees
 * once a user has burned the per-minute budget.
 */
class SwitchableRateLimit {
  allowed = true;
  readonly retryAfterSeconds = 42;

  async consume(): Promise<RateLimitDecision> {
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

interface SessionEntry {
  readonly id: string;
  readonly deviceLabel: string | null;
  readonly createdAt: string;
  readonly lastUsedAt: string;
  readonly expiresAt: string;
  readonly current: boolean;
}

function setCookies(response: request.Response): string[] {
  const header: unknown = response.headers['set-cookie'];

  if (Array.isArray(header)) return header as string[];

  return typeof header === 'string' ? [header] : [];
}

function refreshCookie(response: request.Response): string {
  for (const cookie of setCookies(response)) {
    const pair = cookie.split(';')[0] ?? '';

    if (
      pair.startsWith(`${REFRESH_COOKIE_NAME}=`) &&
      pair.length > REFRESH_COOKIE_NAME.length + 1
    ) {
      return pair;
    }
  }

  throw new Error('no refresh cookie in the response');
}

function refreshTokenOf(response: request.Response): string {
  return refreshCookie(response).slice(REFRESH_COOKIE_NAME.length + 1);
}

function clearedCookie(response: request.Response): string | null {
  return (
    setCookies(response).find((cookie) => cookie.startsWith(`${REFRESH_COOKIE_NAME}=;`)) ?? null
  );
}

function entriesOf(response: request.Response): SessionEntry[] {
  expect(response.status).toBe(200);

  const body = response.body as { sessions?: SessionEntry[] };

  if (!Array.isArray(body.sessions)) throw new Error('the list had no sessions array');

  return body.sessions;
}

const bearer = (accessToken: string): Record<string, string> => ({
  Authorization: `Bearer ${accessToken}`,
});

const GENERIC_UNAUTHORIZED = {
  statusCode: 401,
  message: 'Unauthorized',
  requestId: expect.any(String) as string,
};

const GENERIC_NOT_FOUND = {
  statusCode: 404,
  message: 'Not Found',
  requestId: expect.any(String) as string,
};

describe('Session management over HTTP (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;

  const server = () => request(app.getHttpServer());

  const register = async (username: string = USERNAME, phone: string = PHONE) =>
    server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

  const registerOk = async (username: string = USERNAME, phone: string = PHONE) => {
    const response = await register(username, phone);

    expect(response.status).toBe(200);

    return response;
  };

  const loginOk = async (phone: string = PHONE) => {
    const response = await server()
      .post('/auth/login')
      .send({ proof: await proofs.issue(phone, 'login') });

    expect(response.status).toBe(200);

    return response;
  };

  const listOk = async (accessToken: string) =>
    entriesOf(await server().get('/auth/sessions').set(bearer(accessToken)));

  const accessTokenOf = (response: request.Response): string =>
    (response.body as { accessToken: string }).accessToken;

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    app = await createTestApp(
      {},
      {
        sessionRepository: sessions,
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: new SwitchableRateLimit() as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  beforeEach(() => {
    sessions.users.clear();
    sessions.sessions.clear();
    sessions.refreshTokens.clear();
    sessions.revokedSessions.length = 0;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('access control', () => {
    it('refuses every session route without an access token', async () => {
      const responses = [
        await server().get('/auth/sessions'),
        await server().delete(`/auth/sessions/${randomUUID()}`),
        await server().post('/auth/logout-all'),
      ];

      for (const response of responses) {
        expect(response.status).toBe(401);
        expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
      }
    });

    it('refuses a forged bearer token', async () => {
      const response = await server().get('/auth/sessions').set(bearer('not.a.real.jwt.token'));

      expect(response.status).toBe(401);
      expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
    });
  });

  describe('GET /auth/sessions', () => {
    it('lists the caller devices and flags the one holding the token', async () => {
      await registerOk();
      const second = await loginOk();

      const response = await server()
        .get('/auth/sessions')
        .set(bearer(accessTokenOf(second)));
      const entries = entriesOf(response);

      expect(entries).toHaveLength(2);
      expect(entries.filter((entry) => entry.current)).toHaveLength(1);
      expect(Object.keys(entries[0] ?? {})).toEqual([
        'id',
        'deviceLabel',
        'createdAt',
        'lastUsedAt',
        'expiresAt',
        'current',
      ]);
      // The list is a device manager, not a credential dump.
      expect(response.text).not.toContain(refreshTokenOf(second));
    });

    it('lists nothing that belongs to another account', async () => {
      const mine = await registerOk();
      const other = await registerOk('other_user', OTHER_PHONE);

      await loginOk(OTHER_PHONE);

      const mineIds = (await listOk(accessTokenOf(mine))).map((entry) => entry.id);
      const otherIds = (await listOk(accessTokenOf(other))).map((entry) => entry.id);

      // One device for the caller, two for the stranger, and both accounts are
      // in the store at the same time, so a leaked row would show up here.
      expect(mineIds).toHaveLength(1);
      expect(otherIds).toHaveLength(2);
      expect(mineIds.filter((id) => otherIds.includes(id))).toEqual([]);
    });
  });

  describe('DELETE /auth/sessions/:sessionId', () => {
    it('revokes another device and keeps the caller signed in', async () => {
      const first = await registerOk();
      const second = await loginOk();
      const token = accessTokenOf(second);

      const target = (await listOk(token)).find((entry) => !entry.current);
      const response = await server()
        .delete(`/auth/sessions/${target?.id ?? ''}`)
        .set(bearer(token));

      expect(response.status).toBe(204);
      expect(response.text).toBe('');
      // Nothing current was touched, so the caller keeps its cookie.
      expect(clearedCookie(response)).toBeNull();
      expect(sessions.revokedSessions).toEqual([{ sessionId: target?.id, reason: 'user_revoked' }]);

      // The dropped device cannot rotate any more; the caller still can.
      await server().post('/auth/refresh').set('Cookie', refreshCookie(first)).expect(401);
      await server().post('/auth/refresh').set('Cookie', refreshCookie(second)).expect(200);
      expect(await listOk(token)).toHaveLength(1);
    });

    it('clears the cookie when the caller revokes its own session', async () => {
      const registered = await registerOk();
      const token = accessTokenOf(registered);
      const own = (await listOk(token)).find((entry) => entry.current);

      const response = await server()
        .delete(`/auth/sessions/${own?.id ?? ''}`)
        .set(bearer(token));

      expect(response.status).toBe(204);
      expect(clearedCookie(response)).toContain(`${REFRESH_COOKIE_NAME}=;`);
      // The control case for every refused id: the route revokes a real,
      // owned session.
      expect(sessions.revokedSessions).toEqual([{ sessionId: own?.id, reason: 'user_revoked' }]);

      // The access token dies with the session it was issued for.
      await server().get('/auth/sessions').set(bearer(token)).expect(401);
    });

    it('answers the same 404 for unknown, malformed and foreign ids', async () => {
      const mine = await registerOk();
      const other = await registerOk('other_user', OTHER_PHONE);
      const token = accessTokenOf(mine);
      const foreignId = (await listOk(accessTokenOf(other)))[0]?.id ?? randomUUID();

      const unknown = await server().delete(`/auth/sessions/${randomUUID()}`).set(bearer(token));
      const malformed = await server().delete('/auth/sessions/not-a-uuid').set(bearer(token));
      const foreign = await server().delete(`/auth/sessions/${foreignId}`).set(bearer(token));

      const attempts = [unknown, malformed, foreign];

      for (const response of attempts) {
        expect(response.status).toBe(404);
        expect(response.body).toEqual(GENERIC_NOT_FOUND);
      }

      // Ignoring the per-request id, a foreign id is indistinguishable from a
      // random one and from a value that is not an id at all.
      const bodies = attempts.map((response) => {
        const body: Record<string, unknown> = { ...(response.body as Record<string, unknown>) };

        delete body.requestId;

        return body;
      });

      expect(bodies).toHaveLength(3);
      expect(bodies[1]).toEqual(bodies[0]);
      expect(bodies[2]).toEqual(bodies[0]);

      // The stranger's session survived every attempt: the owner still
      // authenticates with its token and the id is still active.
      const strangerSessions = await listOk(accessTokenOf(other));

      expect(strangerSessions.map((entry) => entry.id)).toEqual([foreignId]);
      expect(sessions.revokedSessions).toHaveLength(0);
    });
  });

  describe('POST /auth/logout-all', () => {
    it('revokes every device and clears the cookie', async () => {
      const first = await registerOk();
      const second = await loginOk();

      const response = await server()
        .post('/auth/logout-all')
        .set(bearer(accessTokenOf(second)));

      expect(response.status).toBe(204);
      expect(clearedCookie(response)).toContain(`${REFRESH_COOKIE_NAME}=;`);

      await server()
        .get('/auth/sessions')
        .set(bearer(accessTokenOf(first)))
        .expect(401);
      await server().post('/auth/refresh').set('Cookie', refreshCookie(first)).expect(401);
      await server().post('/auth/refresh').set('Cookie', refreshCookie(second)).expect(401);
      expect(sessions.revokedSessions.map((entry) => entry.reason)).toEqual([
        'logout_all',
        'logout_all',
      ]);
    });

    it('leaves other accounts signed in', async () => {
      const mine = await registerOk();
      const other = await registerOk('other_user', OTHER_PHONE);

      await server()
        .post('/auth/logout-all')
        .set(bearer(accessTokenOf(mine)))
        .expect(204);

      await server()
        .get('/auth/sessions')
        .set(bearer(accessTokenOf(other)))
        .expect(200);
      await server().post('/auth/refresh').set('Cookie', refreshCookie(other)).expect(200);
    });
  });
});

describe('Session route rate limiting (e2e)', () => {
  let app: NestExpressApplication;
  let limiter: SwitchableRateLimit;
  let proofs: ProofTokenService;

  const server = () => request(app.getHttpServer());

  beforeAll(async () => {
    limiter = new SwitchableRateLimit();
    app = await createTestApp(
      {},
      {
        sessionRepository: new InMemorySessionRepository(),
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: limiter as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('answers 429 with Retry-After once the per-user budget is gone', async () => {
    const registered = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(PHONE, 'register'), username: USERNAME });
    const token = (registered.body as { accessToken: string }).accessToken;
    const sessionId =
      entriesOf(await server().get('/auth/sessions').set(bearer(token)))[0]?.id ?? '';

    limiter.allowed = false;

    const responses = [
      await server().get('/auth/sessions').set(bearer(token)),
      await server().delete(`/auth/sessions/${sessionId}`).set(bearer(token)),
      await server().post('/auth/logout-all').set(bearer(token)),
    ];

    for (const response of responses) {
      expect(response.status).toBe(429);
      expect(response.headers['retry-after']).toBe('42');
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: expect.any(String) as string,
      });
    }
  });
});
