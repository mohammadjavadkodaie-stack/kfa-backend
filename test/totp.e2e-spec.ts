import type { NestExpressApplication } from '@nestjs/platform-express';
import { PinoLogger } from 'nestjs-pino';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { InMemoryTotpRepository } from '../src/auth/totp/in-memory-totp.repository';
import { STEPUP_WINDOW_MS } from '../src/auth/totp/step-up.guard';
import { base32Decode, totpAt } from '../src/auth/totp/totp';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
  ResetRateLimitInput,
} from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * The second-factor endpoints over HTTP, with no database and no Redis: the
 * session store and the credential store are in memory, so a spec can read the
 * stamps and the hashes the API wrote.
 *
 * What must hold:
 * - staff only (ADMIN/OWNER), never a fresh enrolment for a non-staff account,
 * - the secret leaves exactly once, in the enrolment answer,
 * - every failure of confirm and stepup answers with the same generic 401,
 * - the step-up opens for one session and one code only, and a replay fails,
 * - nothing that carries a secret may be cached.
 */

/** Matches the generic refusal the filter produces for a plain 401. */
const UNAUTHORIZED = { statusCode: 401, message: 'Unauthorized' } as const;
const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;

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
 * Fixed-window limiter without Redis. Only the second-factor verifier budget is
 * enforced; the per-IP budgets of register/login keep their own suites and would
 * otherwise refuse the eleventh account this suite has to create.
 */
const ENFORCED_SCOPES: ReadonlySet<string> = new Set(['totp-verify-user']);

class CountingRateLimit {
  private readonly counters = new Map<string, number>();

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    if (!ENFORCED_SCOPES.has(input.scope)) {
      return { allowed: true, remaining: input.limit, retryAfterSeconds: 0 };
    }

    const key = `${input.scope}:${input.identifier}`;
    const hits = (this.counters.get(key) ?? 0) + 1;

    this.counters.set(key, hits);

    return hits <= input.limit
      ? { allowed: true, remaining: Math.max(0, input.limit - hits), retryAfterSeconds: 0 }
      : { allowed: false, remaining: 0, retryAfterSeconds: input.windowSeconds };
  }

  async reset(input: ResetRateLimitInput): Promise<void> {
    this.counters.delete(`${input.scope}:${input.identifier}`);
  }
}

interface Account {
  readonly token: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly username: string;
  readonly phone: string;
}

interface Enrolled {
  readonly secretBase32: string;
  readonly secret: Buffer;
  readonly recoveryCodes: string[];
}

describe('TOTP endpoints (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let credentials: InMemoryTotpRepository;
  let proofs: ProofTokenService;
  let sequence = 0;

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

  /** Every second-factor answer is uncacheable, refusals included. */
  function expectNoStore(response: { headers: Record<string, string | undefined> }): void {
    expect(response.headers['cache-control']).toBe('no-store');
  }

  /** Registers a real account and returns the credential the API issued. */
  async function signUp(role: Role = Role.USER): Promise<Account> {
    sequence += 1;
    const username = `totp_user_${sequence}`;
    const phone = `+1415777${String(1_000 + sequence).padStart(4, '0')}`;

    const response = await post('/auth/register', undefined, {
      proof: await proofs.issue(phone, 'register'),
      username,
    });

    expect(response.status).toBe(200);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`user ${username} was not stored`);

    sessions.setUserRole(stored.id, { role });

    const session = [...sessions.sessions.values()].find(
      (candidate) => candidate.userId === stored.id,
    );

    if (session === undefined) throw new Error(`session of ${username} was not stored`);

    return {
      token: (response.body as { accessToken: string }).accessToken,
      userId: stored.id,
      sessionId: session.id,
      username,
      phone,
    };
  }

  const staff = (role: Role = Role.ADMIN) => signUp(role);

  /** Enrolment plus confirmation, the state every step-up test starts from. */
  async function enrollAndConfirm(account: Account): Promise<Enrolled> {
    const enroll = await post('/auth/totp/enroll', account.token);

    expect(enroll.status).toBe(200);

    const secretBase32 = (enroll.body as { secretBase32: string }).secretBase32;
    const secret = base32Decode(secretBase32);

    const confirm = await post('/auth/totp/confirm', account.token, {
      code: totpAt(secret, Date.now()),
    });

    expect(confirm.status).toBe(200);

    return {
      secretBase32,
      secret,
      recoveryCodes: (confirm.body as { recoveryCodes: string[] }).recoveryCodes,
    };
  }

  /**
   * A code for the next time step: the step used to confirm is spent, and the
   * service refuses any code that is not newer than the last accepted one.
   */
  const freshCode = (secret: Buffer): string => totpAt(secret, Date.now() + 30_000);

  /**
   * Enrolment itself stamps the session, so this pulls that stamp past the
   * five-minute window: the state a sensitive action is refused in.
   */
  function expireStepUp(account: Account): Date {
    const session = sessions.sessions.get(account.sessionId);

    if (session === undefined) throw new Error('missing session');

    session.stepupAt = new Date(Date.now() - STEPUP_WINDOW_MS);

    return session.stepupAt;
  }

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    credentials = new InMemoryTotpRepository();
    app = await createTestApp(
      {},
      {
        sessionRepository: sessions,
        totpRepository: credentials,
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: new CountingRateLimit() as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('refuses anonymous callers on all four routes', async () => {
    const responses = [
      await get('/auth/totp/status'),
      await post('/auth/totp/enroll'),
      await post('/auth/totp/confirm', undefined, { code: '123456' }),
      await post('/auth/totp/stepup', undefined, { code: '123456' }),
    ];

    for (const response of responses) {
      expect(response.status).toBe(401);
      expect(response.body).toMatchObject(UNAUTHORIZED);
      expectNoStore(response);
    }
  });

  it('refuses the second factor to accounts that are not staff', async () => {
    for (const role of [Role.USER, Role.ATHLETE]) {
      const account = await signUp(role);

      for (const response of [
        await get('/auth/totp/status', account.token),
        await post('/auth/totp/enroll', account.token),
        await post('/auth/totp/confirm', account.token, { code: '123456' }),
        await post('/auth/totp/stepup', account.token, { code: '123456' }),
      ]) {
        expect(response.status).toBe(403);
        expect(response.body).toMatchObject(FORBIDDEN);
        // No secret reaches a caller the route was never meant for.
        expect(JSON.stringify(response.body)).not.toContain('secret');
        expectNoStore(response);
      }

      // Nothing was written on the way to the refusal.
      expect(await credentials.getCredential(account.userId)).toBeNull();
    }
  });

  it('reports an empty status, then enrols, confirms once and releases ten codes', async () => {
    const account = await staff();

    const before = await get('/auth/totp/status', account.token);

    expect(before.status).toBe(200);
    expect(before.body).toEqual({ confirmed: false, recoveryCodesLeft: 0 });
    expectNoStore(before);

    const enroll = await post('/auth/totp/enroll', account.token);

    expect(enroll.status).toBe(200);
    expectNoStore(enroll);

    const { secretBase32, otpauthUri } = enroll.body as {
      secretBase32: string;
      otpauthUri: string;
    };

    expect(Object.keys(enroll.body as object).sort()).toEqual(['otpauthUri', 'secretBase32']);
    expect(otpauthUri).toBe(
      `otpauth://totp/KFA:${encodeURIComponent(account.username)}` +
        `?secret=${secretBase32}&issuer=KFA&algorithm=SHA1&digits=6&period=30`,
    );
    // The phone number identified the account at signup; it is not a label here.
    expect(otpauthUri).not.toContain(account.phone.replace('+', '').slice(-6));

    const pending = await get('/auth/totp/status', account.token);

    expect(pending.body).toEqual({ confirmed: false, recoveryCodesLeft: 0 });

    const secret = base32Decode(secretBase32);
    const confirm = await post('/auth/totp/confirm', account.token, {
      code: totpAt(secret, Date.now()),
    });

    expect(confirm.status).toBe(200);
    expectNoStore(confirm);

    const { recoveryCodes } = confirm.body as { recoveryCodes: string[] };

    expect(Object.keys(confirm.body as object)).toEqual(['recoveryCodes']);
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);

    for (const code of recoveryCodes) {
      expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    }

    expect(confirm.body).not.toHaveProperty('secretBase32');

    const after = await get('/auth/totp/status', account.token);

    expect(after.body).toEqual({ confirmed: true, recoveryCodesLeft: 10 });
    expect(JSON.stringify(after.body)).not.toContain(secretBase32);

    // The codes are stored hashed, and never twice.
    const stored = await credentials.getCredential(account.userId);

    expect(stored?.confirmedAt).toBeInstanceOf(Date);
    expect(stored?.secretEnc).not.toContain(secretBase32);
    expect(JSON.stringify(stored)).not.toContain(recoveryCodes[0]?.replace('-', ''));
  });

  it('refuses a second confirmation and a second enrolment', async () => {
    const account = await staff();
    const enrolled = await enrollAndConfirm(account);

    const again = await post('/auth/totp/confirm', account.token, {
      code: freshCode(enrolled.secret),
    });

    expect(again.status).toBe(401);
    expect(again.body).toMatchObject(UNAUTHORIZED);

    const renew = await post('/auth/totp/enroll', account.token);

    expect(renew.status).toBe(409);
    expect(JSON.stringify(renew.body)).not.toContain(enrolled.secretBase32);
    expectNoStore(renew);

    // The confirmed credential survived both refusals.
    expect((await get('/auth/totp/status', account.token)).body).toEqual({
      confirmed: true,
      recoveryCodesLeft: 10,
    });
  });

  it('answers a wrong code and a malformed body with the same 401', async () => {
    const account = await staff();

    await enrollAndConfirm(account);

    const responses = [
      await post('/auth/totp/confirm', account.token, { code: '000000' }),
      await post('/auth/totp/stepup', account.token, { code: '000000' }),
      await post('/auth/totp/stepup', account.token, { code: '12345678901234567890' }),
      await post('/auth/totp/stepup', account.token, { code: 'abcdef' }),
      await post('/auth/totp/stepup', account.token, { code: '' }),
    ];

    for (const response of responses) {
      expect(response.status).toBe(401);
      expectNoStore(response);
    }

    const shapes = new Set(
      responses.map((response) =>
        JSON.stringify({ ...(response.body as object), requestId: undefined }),
      ),
    );

    expect(shapes.size).toBe(1);
    expect(JSON.parse([...shapes][0] ?? '{}')).toMatchObject(UNAUTHORIZED);
  });

  it('rejects a body that is not exactly the code field, as a failed attempt', async () => {
    const account = await staff();

    await enrollAndConfirm(account);

    // Enrolment stamped this session; a failed step-up must not move it.
    const stamped = await sessions.getStepUpAt(account.sessionId, account.userId);

    // A caller cannot name another account: the user always comes from the token,
    // and an unexpected field makes the whole body unusable, not a new target.
    for (const body of [
      {},
      { code: '123456', userId: account.userId },
      { code: '123456', sessionId: account.sessionId },
      [1, 2, 3],
      'code=123456',
    ]) {
      const response = await post('/auth/totp/stepup', account.token, body);

      expect(response.status).toBe(401);
      expect(response.body).toEqual({
        statusCode: 401,
        message: 'Unauthorized',
        requestId: expect.any(String),
      });
      expect(JSON.stringify(response.body)).not.toContain(account.userId);
      expectNoStore(response);
    }

    expect(await sessions.getStepUpAt(account.sessionId, account.userId)).toEqual(stamped);

    // The enrolment takes no input at all, and an unexpected field is malformed.
    const other = await staff();

    expect((await post('/auth/totp/enroll', other.token, { label: 'laptop' })).status).toBe(400);
  });

  it('opens the step-up for the session that proved the code, and only once', async () => {
    const account = await staff();
    const enrolled = await enrollAndConfirm(account);
    const code = freshCode(enrolled.secret);
    const expired = expireStepUp(account);

    // Before the step-up the sensitive route is closed, with a code the app can act on.
    const closed = await get('/test/sensitive', account.token);

    expect(closed.status).toBe(403);
    expect(closed.body).toEqual({
      statusCode: 403,
      message: 'Forbidden',
      requestId: expect.any(String),
      code: 'step_up_required',
    });
    expect(await sessions.getStepUpAt(account.sessionId, account.userId)).toEqual(expired);

    const stepup = await post('/auth/totp/stepup', account.token, { code });

    expect(stepup.status).toBe(200);
    expect(stepup.body).toEqual({ ok: true, validForSeconds: 300 });
    expectNoStore(stepup);

    const stamp = await sessions.getStepUpAt(account.sessionId, account.userId);

    expect(stamp).toBeInstanceOf(Date);

    const open = await get('/test/sensitive', account.token);

    expect(open.status).toBe(200);
    expect(open.body).toEqual({ ok: true });

    // The same code cannot buy a second window.
    const replay = await post('/auth/totp/stepup', account.token, { code });

    expect(replay.status).toBe(401);
    expect(replay.body).toMatchObject(UNAUTHORIZED);
    expect(await sessions.getStepUpAt(account.sessionId, account.userId)).toEqual(stamp);
  });

  it('spends a recovery code once and lowers the remaining count', async () => {
    const account = await staff();
    const enrolled = await enrollAndConfirm(account);
    const recoveryCode = enrolled.recoveryCodes[0] ?? '';

    const first = await post('/auth/totp/stepup', account.token, { code: recoveryCode });

    expect(first.status).toBe(200);
    expect(first.body).toEqual({ ok: true, validForSeconds: 300 });

    const reused = await post('/auth/totp/stepup', account.token, { code: recoveryCode });

    expect(reused.status).toBe(401);

    const status = await get('/auth/totp/status', account.token);

    expect(status.body).toEqual({ confirmed: true, recoveryCodesLeft: 9 });
  });

  it('locks a user out after five wrong codes, without saying so', async () => {
    const account = await staff();
    const enrolled = await enrollAndConfirm(account);
    const stamped = await sessions.getStepUpAt(account.sessionId, account.userId);
    const wrong = await post('/auth/totp/stepup', account.token, { code: '000000' });

    expect(wrong.status).toBe(401);

    for (let attempt = 0; attempt < 4; attempt += 1) {
      await post('/auth/totp/stepup', account.token, { code: '000000' });
    }

    // The sixth attempt carries a correct code and is still refused.
    const locked = await post('/auth/totp/stepup', account.token, {
      code: freshCode(enrolled.secret),
    });

    expect(locked.status).toBe(401);
    expect(locked.body).toEqual({ ...wrong.body, requestId: expect.any(String) });
    expect(await sessions.getStepUpAt(account.sessionId, account.userId)).toEqual(stamped);

    // Lockout spends attempt budget, not recovery codes or the credential.
    expect((await get('/auth/totp/status', account.token)).body).toEqual({
      confirmed: true,
      recoveryCodesLeft: 10,
    });
  });

  it('keeps the code and the secret out of the logs', async () => {
    const info = jest.spyOn(PinoLogger.prototype, 'info');
    const warn = jest.spyOn(PinoLogger.prototype, 'warn');

    try {
      const account = await staff();
      const enrolled = await enrollAndConfirm(account);
      const code = freshCode(enrolled.secret);

      expect((await post('/auth/totp/stepup', account.token, { code })).status).toBe(200);

      const logged = JSON.stringify([...info.mock.calls, ...warn.mock.calls]);

      expect(logged).not.toContain(code);
      expect(logged).not.toContain(enrolled.secretBase32);
      expect(logged).not.toContain(enrolled.recoveryCodes[0] ?? '');
    } finally {
      info.mockRestore();
      warn.mockRestore();
    }
  });
});
