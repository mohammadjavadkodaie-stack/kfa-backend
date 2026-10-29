import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { InMemoryTotpRepository } from '../src/auth/totp/in-memory-totp.repository';
import { base32Decode, totpAt } from '../src/auth/totp/totp';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * The default-deny second-factor gate over HTTP, with no database and no Redis.
 *
 * What must hold:
 * - a staff session that never proved a second factor reaches nothing except
 *   the second-factor routes and logout,
 * - enrolling proves possession, so the enrolling session is usable at once,
 *   while every other session of the same account has to step up,
 * - USER and ATHLETE are untouched, and every refusal is the same bytes.
 */

/** The actionable refusal: the client has to run the second factor. */
const SECOND_FACTOR_REQUIRED = {
  statusCode: 403,
  message: 'Forbidden',
  code: 'second_factor_required',
} as const;

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

interface Account {
  readonly token: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly username: string;
  readonly phone: string;
}

interface Session {
  readonly token: string;
  readonly sessionId: string;
}

interface Enrolled {
  readonly secret: Buffer;
  readonly recoveryCodes: string[];
}

describe('Staff second-factor gate (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let sequence = 0;
  let stepOffset = 0;

  const server = () => request(app.getHttpServer());
  const post = (path: string, token?: string, body: unknown = {}) => {
    const call = server().post(path);

    return (token === undefined ? call : call.set('Authorization', `Bearer ${token}`)).send(
      body as object,
    );
  };
  const get = (path: string, token?: string) => {
    const call = server().get(path);

    return token === undefined ? call : call.set('Authorization', `Bearer ${token}`);
  };

  /** Registers a real account, then moves it to `role` the way an admin would. */
  async function signUp(role: Role): Promise<Account> {
    sequence += 1;
    const username = `gate_user_${sequence}`;
    const phone = `+1415888${String(1_000 + sequence).padStart(4, '0')}`;

    const response = await post('/auth/register', undefined, {
      proof: await proofs.issue(phone, 'register'),
      username,
    });

    expect(response.status).toBe(200);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`user ${username} was not stored`);

    sessions.setUserRole(stored.id, { role });

    const session = [...sessions.sessions.values()].find((row) => row.userId === stored.id);

    if (session === undefined) throw new Error(`session of ${username} was not stored`);

    return {
      token: (response.body as { accessToken: string }).accessToken,
      userId: stored.id,
      sessionId: session.id,
      username,
      phone,
    };
  }

  /** A second device of the same account: a fresh session with no stamp. */
  async function login(account: Account): Promise<Session> {
    const response = await post('/auth/login', undefined, {
      proof: await proofs.issue(account.phone, 'login'),
    });

    expect(response.status).toBe(200);

    const rows = [...sessions.sessions.values()].filter((row) => row.userId === account.userId);
    const newest = rows[rows.length - 1];

    if (newest === undefined) throw new Error('session was not stored');

    return { token: (response.body as { accessToken: string }).accessToken, sessionId: newest.id };
  }

  /** Enrolment plus confirmation; this session proves possession on the way. */
  async function enrollAndConfirm(account: Account): Promise<Enrolled> {
    const enroll = await post('/auth/totp/enroll', account.token);

    expect(enroll.status).toBe(200);

    const secret = base32Decode((enroll.body as { secretBase32: string }).secretBase32);

    const confirm = await post('/auth/totp/confirm', account.token, {
      code: totpAt(secret, Date.now()),
    });

    expect(confirm.status).toBe(200);

    return { secret, recoveryCodes: (confirm.body as { recoveryCodes: string[] }).recoveryCodes };
  }

  /** A code for a time step newer than every code this suite already spent. */
  function nextCode(secret: Buffer): string {
    stepOffset += 1;

    return totpAt(secret, Date.now() + stepOffset * 30_000);
  }

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    app = await createTestApp(
      {},
      {
        sessionRepository: sessions,
        totpRepository: new InMemoryTotpRepository(),
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: new PermissiveRateLimit() as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('refuses a staff session that never proved the second factor', async () => {
    const admin = await signUp(Role.ADMIN);

    const refusal = await get('/test/protected', admin.token);

    expect(refusal.status).toBe(403);
    expect(refusal.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
    expect(JSON.stringify(refusal.body)).not.toContain(admin.userId);
  });

  it('gates every route that is not explicitly opened', async () => {
    const admin = await signUp(Role.ADMIN);

    for (const path of ['/test/protected', '/test/admin', '/auth/sessions']) {
      const refusal = await get(path, admin.token);

      expect(refusal.status).toBe(403);
      expect(refusal.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
    }
  });

  it('leaves the second-factor routes reachable and opens the gate after confirm', async () => {
    const admin = await signUp(Role.ADMIN);

    expect((await get('/auth/totp/status', admin.token)).status).toBe(200);

    const enrolled = await enrollAndConfirm(admin);

    expect(enrolled.recoveryCodes).toHaveLength(10);

    const open = await get('/test/protected', admin.token);

    expect(open.status).toBe(200);
    expect(open.body).toEqual({ ok: true });
  });

  it('gates a second session of the same admin until it steps up', async () => {
    const admin = await signUp(Role.ADMIN);
    const enrolled = await enrollAndConfirm(admin);
    const second = await login(admin);

    const closed = await get('/test/protected', second.token);

    expect(closed.status).toBe(403);
    expect(closed.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });

    // The second factor itself has to stay reachable, or the session is stuck.
    expect((await get('/auth/totp/status', second.token)).status).toBe(200);

    const stepup = await post('/auth/totp/stepup', second.token, {
      code: nextCode(enrolled.secret),
    });

    expect(stepup.status).toBe(200);
    expect((await get('/test/protected', second.token)).status).toBe(200);

    // The session that enrolled was never closed in the meantime.
    expect((await get('/test/protected', admin.token)).status).toBe(200);
  });

  it('lifts the gate with a recovery code once', async () => {
    const admin = await signUp(Role.ADMIN);
    const enrolled = await enrollAndConfirm(admin);
    const recoveryCode = enrolled.recoveryCodes[0] ?? '';
    const second = await login(admin);

    expect((await post('/auth/totp/stepup', second.token, { code: recoveryCode })).status).toBe(
      200,
    );
    expect((await get('/test/protected', second.token)).status).toBe(200);

    // The same code is worthless on another session.
    const third = await login(admin);

    expect((await post('/auth/totp/stepup', third.token, { code: recoveryCode })).status).toBe(401);
    expect((await get('/test/protected', third.token)).status).toBe(403);
  });

  it('lets a staff session log out without a step-up', async () => {
    const admin = await signUp(Role.ADMIN);

    expect((await get('/test/protected', admin.token)).status).toBe(403);
    expect((await post('/auth/logout', admin.token)).status).toBe(204);

    const other = await signUp(Role.ADMIN);

    expect((await post('/auth/logout-all', other.token)).status).toBe(204);
  });

  it('treats an OWNER like an ADMIN', async () => {
    const owner = await signUp(Role.OWNER);

    expect((await get('/test/protected', owner.token)).status).toBe(403);

    await enrollAndConfirm(owner);

    expect((await get('/test/protected', owner.token)).status).toBe(200);
  });

  it('leaves USER and ATHLETE untouched', async () => {
    for (const role of [Role.USER, Role.ATHLETE]) {
      const account = await signUp(role);
      const response = await get('/test/protected', account.token);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ ok: true });
    }
  });

  it('answers every denial with the same bytes apart from the request id', async () => {
    const refusals: { body: unknown; account: Account }[] = [];

    for (const role of [Role.ADMIN, Role.OWNER]) {
      const account = await signUp(role);

      refusals.push({ body: (await get('/test/protected', account.token)).body, account });
    }

    for (const { body, account } of refusals) {
      expect(body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });

      const text = JSON.stringify({ ...(body as object), requestId: '-' });

      // No role, no second-factor state, no counts, no identity.
      expect(text).not.toMatch(/ADMIN|OWNER|role|confirmed|recovery|totp/i);
      expect(text).not.toContain(account.userId);
      expect(text).not.toContain(account.sessionId);
    }

    expect(
      new Set(refusals.map(({ body }) => JSON.stringify({ ...(body as object), requestId: '-' })))
        .size,
    ).toBe(1);
  });
});
