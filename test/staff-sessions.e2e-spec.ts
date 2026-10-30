import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { REFRESH_COOKIE_NAME } from '../src/auth/token/refresh-token';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * Staff session policy over HTTP, with no database and no Redis.
 *
 * ADMIN and OWNER sessions get the short cap and the idle limit, while USER and
 * ATHLETE keep exactly the lifetime they had before. Idleness is reached by
 * moving the stored activity stamp, so no test has to wait for a clock.
 */

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const STAFF_HOURS = 2;
const STAFF_IDLE_MINUTES = 30;

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

/** The explicit limiter is out of scope here: always admit. */
class PermissiveRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
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

/** The refusal is generic: it never says which limit was hit. */
const GENERIC_UNAUTHORIZED = { error: 'invalid_credentials' };

describe('Staff session policy over HTTP (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let sequence = 0;

  const server = () => request(app.getHttpServer());

  /**
   * Registers a real account, moves it to `role` the way an admin would and
   * signs in again, because the session created at registration is a USER one.
   */
  async function signIn(
    role: Role,
  ): Promise<{ userId: string; sessionId: string; cookie: string }> {
    sequence += 1;
    const username = `lifetime_user_${sequence}`;
    const phone = `+1415777${String(1_000 + sequence).padStart(4, '0')}`;

    const registered = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

    expect(registered.status).toBe(200);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`user ${username} was not stored`);

    sessions.setUserRole(stored.id, { role });

    const loggedIn = await server()
      .post('/auth/login')
      .send({ proof: await proofs.issue(phone, 'login') });

    expect(loggedIn.status).toBe(200);

    const rows = [...sessions.sessions.values()].filter((row) => row.userId === stored.id);
    const newest = rows[rows.length - 1];

    if (newest === undefined) throw new Error('session was not stored');

    return { userId: stored.id, sessionId: newest.id, cookie: refreshCookie(loggedIn) };
  }

  function sessionOf(sessionId: string) {
    const session = sessions.sessions.get(sessionId);

    if (session === undefined) throw new Error(`unknown session ${sessionId}`);

    return session;
  }

  /** Moves the recorded activity of a session into the past. */
  function idleFor(sessionId: string, minutes: number): void {
    sessionOf(sessionId).lastUsedAt = new Date(Date.now() - minutes * MINUTE);
  }

  /** Revocations recorded since the previous tests: the store is shared. */
  function revocationsSince(baseline: number): { sessionId: string; reason: string }[] {
    return sessions.revokedSessions.slice(baseline);
  }

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    app = await createTestApp(
      {
        STAFF_SESSION_ABSOLUTE_HOURS: String(STAFF_HOURS),
        STAFF_SESSION_IDLE_MINUTES: String(STAFF_IDLE_MINUTES),
      },
      {
        sessionRepository: sessions,
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: new PermissiveRateLimit() as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  it.each([Role.ADMIN, Role.OWNER])(
    'caps a fresh %s session at the staff lifetime',
    async (role) => {
      const { sessionId } = await signIn(role);
      const left = sessionOf(sessionId).expiresAt.getTime() - Date.now();

      expect(left).toBeGreaterThan(STAFF_HOURS * HOUR - MINUTE);
      expect(left).toBeLessThanOrEqual(STAFF_HOURS * HOUR);
    },
  );

  it.each([Role.USER, Role.ATHLETE])('leaves a %s session on the normal cap', async (role) => {
    const { sessionId } = await signIn(role);
    const left = sessionOf(sessionId).expiresAt.getTime() - Date.now();

    expect(left).toBeGreaterThan(29 * DAY);
    expect(left).toBeLessThanOrEqual(30 * DAY);
  });

  it('refuses an idle staff refresh with the generic 401 and revokes the session', async () => {
    const { sessionId, cookie } = await signIn(Role.ADMIN);
    const baseline = sessions.revokedSessions.length;

    idleFor(sessionId, STAFF_IDLE_MINUTES + 1);

    const refused = await server().post('/auth/refresh').set('Cookie', cookie);

    expect(refused.status).toBe(401);
    expect(refused.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(revocationsSince(baseline)).toEqual([{ sessionId, reason: 'idle_timeout' }]);
    // The dead cookie is cleared, so the client re-authenticates.
    expect(setCookies(refused)).toContainEqual(expect.stringContaining(`${REFRESH_COOKIE_NAME}=;`));
    // The session is gone, so its access token is refused from now on.
    expect(sessionOf(sessionId).revokedAt).not.toBeNull();
  });

  it('rotates a staff session just inside the idle limit without extending it', async () => {
    const { sessionId, cookie } = await signIn(Role.OWNER);
    const baseline = sessions.revokedSessions.length;
    const deadline = sessionOf(sessionId).expiresAt.getTime();

    idleFor(sessionId, STAFF_IDLE_MINUTES - 1);

    const rotated = await server().post('/auth/refresh').set('Cookie', cookie);

    expect(rotated.status).toBe(200);
    expect(revocationsSince(baseline)).toHaveLength(0);
    // The cookie moved on, the absolute deadline did not.
    expect(sessionOf(sessionId).expiresAt.getTime()).toBe(deadline);
  });

  it('still refreshes a USER session that idled past the staff limit', async () => {
    const { sessionId, cookie } = await signIn(Role.USER);
    const baseline = sessions.revokedSessions.length;
    const deadline = sessionOf(sessionId).expiresAt.getTime();

    idleFor(sessionId, STAFF_IDLE_MINUTES + 1);

    const rotated = await server().post('/auth/refresh').set('Cookie', cookie);

    expect(rotated.status).toBe(200);
    expect(revocationsSince(baseline)).toHaveLength(0);
    expect(sessionOf(sessionId).expiresAt.getTime()).toBe(deadline);
  });
});
