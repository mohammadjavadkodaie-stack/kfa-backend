import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { EmailProofService } from '../src/auth/email/email-proof';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import type { ProofNonceStore } from '../src/auth/otp/proof-token';
import { REFRESH_COOKIE_NAME } from '../src/auth/token/refresh-token';
import type { RateLimitService } from '../src/rate-limit/rate-limit.service';
import { FakeRateLimit } from './helpers/auth-service-harness';
import { createTestApp } from './helpers/create-test-app';
import { EMAIL_TEST_CODE, createEmailHarness, type EmailHarness } from './helpers/email-harness';

/**
 * The email identity flow over HTTP: `POST /auth/email/start`, `/auth/email/verify`,
 * `/auth/signup` and `/auth/signin`.
 *
 * Every external dependency is replaced: sessions live in memory, codes live in
 * the in-memory store, the transport is the fake adapter, the proof nonces are
 * kept in-process and the explicit limiter always allows. What is left under
 * test is the contract - status codes, the refresh cookie, the challenge for a
 * new device, and the fact that no answer ever carries the address, the
 * password or the mailed code.
 */

const CAPTCHA_TOKEN = 'fake-captcha-pass';
/** Long enough for the policy, and unrelated to the address or the username. */
const PASSWORD = 'kestrel-harbor-quiet-91';
const DEVICE_KEY = 'device-alpha';
const NEW_DEVICE_KEY = 'device-beta';
const ALLOWED_ORIGIN = 'http://localhost:3000';
const FOREIGN_ORIGIN = 'https://evil.example';
const GENERIC_UNAUTHORIZED = { error: 'invalid_credentials' };
const INVALID_CODE = { error: 'invalid_code' };
const DEVICE_REQUIRED = { error: 'device_verification_required' };

/** One audit row as the suite sees it: enough to tell action and metadata apart. */
interface AuditRow {
  readonly action: string;
  readonly metadata: Record<string, unknown>;
  readonly hash: string;
  readonly createdAt: Date;
}

/**
 * In-memory Prisma replacement: `AuditService` keeps its real hashing, chaining
 * and redaction logic, the rows just never leave the process. The email flow
 * fails closed when the trail cannot be written, so it needs a working one.
 */
function createAuditPrisma(): { prisma: object; rows: AuditRow[] } {
  const rows: AuditRow[] = [];

  const tx = {
    $executeRaw: (): Promise<number> => Promise.resolve(1),
    auditLog: {
      findFirst: (): Promise<{ hash: string; createdAt: Date } | null> => {
        const last = rows[rows.length - 1];

        return Promise.resolve(
          last === undefined ? null : { hash: last.hash, createdAt: last.createdAt },
        );
      },
      create: ({ data }: { data: AuditRow }): Promise<AuditRow> => {
        rows.push(data);

        return Promise.resolve(data);
      },
    },
  };

  const prisma = {
    $connect: (): Promise<void> => Promise.resolve(),
    $disconnect: (): Promise<void> => Promise.resolve(),
    $transaction: (callback: (client: typeof tx) => Promise<unknown>): Promise<unknown> =>
      callback(tx),
  };

  return { prisma, rows };
}

/** Nonce store stand-in: `EmailProofService` keeps its real signing logic. */
class InMemoryNonceStore implements ProofNonceStore {
  private readonly nonces = new Map<string, { email: string; expiresAt: number }>();

  async put(jti: string, email: string, ttlSeconds: number): Promise<boolean> {
    this.nonces.set(jti, { email, expiresAt: Date.now() + ttlSeconds * 1_000 });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const stored = this.nonces.get(jti);
    this.nonces.delete(jti);

    return stored === undefined || stored.expiresAt <= Date.now() ? null : stored.email;
  }

  clear(): void {
    this.nonces.clear();
  }
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

/** The generic envelope every refusal that is not a documented body carries. */
function genericError(statusCode: number, message: string): Record<string, unknown> {
  return { statusCode, message, requestId: expect.any(String) as string };
}
const SESSION_FIELDS = ['accessToken', 'expiresIn', 'tokenType'];

describe('Email auth HTTP contract (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let limits: FakeRateLimit;
  let nonces: InMemoryNonceStore;
  let email: EmailHarness;
  let proofs: EmailProofService;
  let auditRows: AuditRow[];

  /** One fresh address (and username) per test: a spent code can never leak into the next one. */
  let mailbox: string;
  let otherMailbox: string;
  let username: string;
  let sequence = 0;

  const server = () => request(app.getHttpServer());

  const start = (address: string = mailbox) =>
    server()
      .post('/auth/email/start')
      .send({ email: address, purpose: 'register', captchaToken: CAPTCHA_TOKEN });

  const verify = (purpose: 'register' | 'login_device', code: string, address: string = mailbox) =>
    server().post('/auth/email/verify').send({ email: address, purpose, code });

  const signUp = (
    proof: string,
    overrides: { username?: string; password?: string; deviceKey?: string } = {},
  ) =>
    server()
      .post('/auth/signup')
      .set('X-Device-Key', overrides.deviceKey ?? DEVICE_KEY)
      .send({
        proof,
        username: overrides.username ?? username,
        password: overrides.password ?? PASSWORD,
        deviceName: 'Laptop',
      });

  const signIn = (
    options: { email?: string; password?: string; deviceKey?: string | null } = {},
  ) => {
    // `null` means the header is absent, which is what a first-time client sends.
    const deviceKey = options.deviceKey === undefined ? DEVICE_KEY : options.deviceKey;
    const pending = server()
      .post('/auth/signin')
      .send({
        email: options.email ?? mailbox,
        password: options.password ?? PASSWORD,
        deviceName: 'Phone',
      });

    return deviceKey === null ? pending : pending.set('X-Device-Key', deviceKey);
  };

  /** The proof the client would get by typing the mailed code. */
  const registerProof = async (address: string = mailbox): Promise<string> => {
    const started = await start(address);

    expect(started.status).toBe(202);

    const verified = await verify('register', EMAIL_TEST_CODE, address);

    expect(verified.status).toBe(200);

    return verified.body.proof as string;
  };

  /** Registration as a client performs it: start, verify, signup. */
  const registerAccount = async (
    options: { email?: string; username?: string } = {},
  ): Promise<request.Response> => {
    const created = await signUp(await registerProof(options.email), {
      username: options.username,
    });

    expect(created.status).toBe(200);

    return created;
  };

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    limits = new FakeRateLimit();
    nonces = new InMemoryNonceStore();
    email = createEmailHarness();
    const audit = createAuditPrisma();
    auditRows = audit.rows;
    app = await createTestApp(
      {},
      {
        prisma: audit.prisma,
        sessionRepository: sessions,
        proofNonceStore: nonces,
        rateLimit: limits as unknown as RateLimitService,
        emailCodeStore: email.store,
        emailProvider: email.provider,
      },
    );
    proofs = app.get(EmailProofService);
  });

  beforeEach(() => {
    sequence += 1;
    mailbox = `ivan${sequence}@example.com`;
    otherMailbox = `boris${sequence}@example.com`;
    username = `ivan${sequence}`;

    sessions.users.clear();
    sessions.sessions.clear();
    sessions.refreshTokens.clear();
    sessions.revokedSessions.length = 0;
    nonces.clear();
    email.provider.clear();
    limits.reset();
    auditRows.length = 0;
  });

  afterAll(async () => {
    await app.close();
  });

  it('registers over email: start, verify, signup, then /auth/me returns the username', async () => {
    const started = await start();

    expect(started.status).toBe(202);
    expect(started.body).toEqual({ ok: true });
    expect(started.headers['cache-control']).toBe('no-store');

    const verified = await verify('register', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);
    expect(verified.headers['cache-control']).toBe('no-store');
    expect(Object.keys(verified.body)).toEqual(['proof']);
    expect(typeof verified.body.proof).toBe('string');

    const created = await signUp(verified.body.proof);

    expect(created.status).toBe(200);
    expect(Object.keys(created.body).sort()).toEqual(SESSION_FIELDS);
    expect(created.body.tokenType).toBe('Bearer');
    expect(refreshCookie(created)).not.toBeNull();

    const me = await server()
      .get('/auth/me')
      .set('Authorization', `Bearer ${created.body.accessToken as string}`);

    expect(me.status).toBe(200);
    expect(me.body).toEqual({
      username,
      role: 'USER',
      status: 'ACTIVE',
      hasAthleteProfile: false,
    });

    // The verification is on the trail, with a masked address and nothing else.
    const trail = JSON.stringify(auditRows.map((row) => row.metadata));

    expect(auditRows.map((row) => row.action)).toContain('email_code.verified');
    expect(trail).not.toContain(mailbox);
    expect(trail).not.toContain(EMAIL_TEST_CODE);
  });

  it('answers the same status and body for an existing and an unknown address', async () => {
    await registerAccount();

    const existing = await start(mailbox);
    const unknown = await start(otherMailbox);

    expect(existing.status).toBe(202);
    expect(unknown.status).toBe(existing.status);
    expect(unknown.body).toEqual(existing.body);
  });

  it('refuses a malformed address with 400', async () => {
    const response = await start('not-an-address');

    expect(response.status).toBe(400);
    expect(response.body).toEqual(genericError(400, 'Bad Request'));
  });

  it('refuses unknown body keys on all four routes with 400', async () => {
    const refused = [
      await server()
        .post('/auth/email/start')
        .send({ email: mailbox, purpose: 'register', captchaToken: CAPTCHA_TOKEN, extra: true }),
      await server()
        .post('/auth/email/verify')
        .send({ email: mailbox, purpose: 'register', code: EMAIL_TEST_CODE, extra: true }),
      await server().post('/auth/signup').send({
        proof: 'whatever',
        username,
        password: PASSWORD,
        deviceName: 'Laptop',
        extra: true,
      }),
      await server().post('/auth/signin').send({
        email: mailbox,
        password: PASSWORD,
        deviceName: 'Phone',
        extra: true,
      }),
    ];

    for (const response of refused) expect(response.status).toBe(400);

    // The verify route answers its own code, the other three keep the generic envelope.
    expect(refused[1]?.body).toEqual(INVALID_CODE);

    for (const response of [refused[0], refused[2], refused[3]]) {
      expect(response?.body).toEqual(genericError(400, 'Bad Request'));
    }
  });

  it('answers invalid_code for a wrong code, identically for an unknown address', async () => {
    await start();

    const wrong = await verify('register', '000000');
    const unknown = await verify('register', '000000', otherMailbox);

    expect(wrong.status).toBe(400);
    expect(wrong.body).toEqual(INVALID_CODE);
    expect(unknown.status).toBe(400);
    expect(unknown.body).toEqual(INVALID_CODE);
  });

  it('locks the code after the attempt budget, even for the right code', async () => {
    await start();

    const maxAttempts = Number(process.env.EMAIL_CODE_MAX_ATTEMPTS ?? 5);
    const attempts = [];

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      attempts.push(await verify('register', '000000'));
    }

    for (const attempt of attempts) {
      expect(attempt.status).toBe(400);
      expect(attempt.body).toEqual(INVALID_CODE);
    }

    const lockedOut = await verify('register', EMAIL_TEST_CODE);

    expect(lockedOut.status).toBe(400);
    expect(lockedOut.body).toEqual(INVALID_CODE);
    expect(auditRows.map((row) => row.action)).toContain('email_code.locked');
  });

  it('refuses a weak password with the reason and creates nothing', async () => {
    const proof = await registerProof();

    const response = await signUp(proof, { password: 'short' });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: 'weak_password', reason: 'too_short' });
    expect(sessions.users.size).toBe(0);
  });

  it('refuses an invalid or an already spent proof with 401', async () => {
    const invalid = await signUp('not-a-proof');

    expect(invalid.status).toBe(401);
    expect(invalid.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(sessions.users.size).toBe(0);

    const proof = await registerProof();
    const created = await signUp(proof);

    expect(created.status).toBe(200);

    const reused = await signUp(proof, { username: `${username}x` });

    expect(reused.status).toBe(401);
    expect(reused.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(sessions.users.size).toBe(1);
  });

  it('answers one generic conflict for a taken username and for a taken address', async () => {
    await registerAccount();

    const takenUsername = await signUp(await registerProof(otherMailbox));

    expect(takenUsername.status).toBe(409);
    expect(takenUsername.body).toEqual({ error: 'unavailable' });

    const takenAddress = await signUp(
      await proofs.issueEmailProof({ email: mailbox, purpose: 'register' }),
      { username: `${username}x` },
    );

    expect(takenAddress.status).toBe(409);
    expect(takenAddress.body).toEqual(takenUsername.body);
  });

  it('challenges a sign-in from a new device with 403 and sends a code', async () => {
    await registerAccount();
    email.provider.clear();

    const challenged = await signIn({ deviceKey: NEW_DEVICE_KEY });

    expect(challenged.status).toBe(403);
    expect(challenged.body).toEqual(DEVICE_REQUIRED);
    expect(refreshCookie(challenged)).toBeNull();
    expect(email.provider.lastCode(mailbox, 'login_device')).toBe(EMAIL_TEST_CODE);
  });

  it('accepts the sign-in once the device has proved the mailed code', async () => {
    await registerAccount();

    const challenged = await signIn({ deviceKey: NEW_DEVICE_KEY });

    expect(challenged.status).toBe(403);

    const verified = await verify('login_device', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);

    // Without the proof the challenge still stands; with it the sign-in goes through.
    const withoutProof = await signIn({ deviceKey: NEW_DEVICE_KEY });

    expect(withoutProof.status).toBe(403);

    const withProof = await server()
      .post('/auth/signin')
      .set('X-Device-Key', NEW_DEVICE_KEY)
      .send({
        email: mailbox,
        password: PASSWORD,
        deviceName: 'Phone',
        proof: verified.body.proof as string,
      });

    expect(withProof.status).toBe(200);
    expect(Object.keys(withProof.body).sort()).toEqual(SESSION_FIELDS);
    expect(refreshCookie(withProof)).not.toBeNull();

    // The device is now bound: the next sign-in needs no proof.
    const again = await signIn({ deviceKey: NEW_DEVICE_KEY });

    expect(again.status).toBe(200);
    expect(refreshCookie(again)).not.toBeNull();
  });

  it('answers one generic 401 for a wrong password and for an unknown address', async () => {
    await registerAccount();

    const wrongPassword = await signIn({ password: 'kestrel-harbor-quiet-92' });
    const unknownAddress = await signIn({ email: otherMailbox });

    expect(wrongPassword.status).toBe(401);
    expect(wrongPassword.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(refreshCookie(wrongPassword)).toBeNull();
    expect(unknownAddress.status).toBe(401);
    expect(unknownAddress.body).toEqual(wrongPassword.body);
    expect(refreshCookie(unknownAddress)).toBeNull();
  });

  it('challenges a sign-in that carries no device key at all', async () => {
    await registerAccount();
    email.provider.clear();

    const challenged = await signIn({ deviceKey: null });

    expect(challenged.status).toBe(403);
    expect(challenged.body).toEqual(DEVICE_REQUIRED);
    expect(refreshCookie(challenged)).toBeNull();
    expect(email.provider.lastCode(mailbox, 'login_device')).toBe(EMAIL_TEST_CODE);
  });

  it('rotates the cookie of an email session when the device key matches', async () => {
    const created = await registerAccount();
    const firstCookie = refreshCookie(created);

    expect(firstCookie).not.toBeNull();

    const rotated = await server()
      .post('/auth/refresh')
      .set('Cookie', firstCookie as string)
      .set('X-Device-Key', DEVICE_KEY);

    expect(rotated.status).toBe(200);
    expect(refreshCookie(rotated)).not.toBeNull();
    expect(refreshCookie(rotated)).not.toBe(firstCookie);

    // The rotated cookie belongs to the device that rotated it, and to no other.
    const otherDevice = await server()
      .post('/auth/refresh')
      .set('Cookie', refreshCookie(rotated) as string)
      .set('X-Device-Key', NEW_DEVICE_KEY);

    expect(otherDevice.status).toBe(401);
    expect(otherDevice.body).toEqual(GENERIC_UNAUTHORIZED);
  });

  it('refuses signup and signin from a foreign origin, and allows an allowlisted one', async () => {
    const refused = [
      await server()
        .post('/auth/signup')
        .set('Origin', FOREIGN_ORIGIN)
        .send({ proof: 'whatever', username, password: PASSWORD, deviceName: 'Browser' }),
      await server()
        .post('/auth/signin')
        .set('Origin', FOREIGN_ORIGIN)
        .send({ email: mailbox, password: PASSWORD, deviceName: 'Browser' }),
    ];

    for (const response of refused) {
      expect(response.status).toBe(403);
      expect(response.body).toEqual(genericError(403, 'Forbidden'));
    }

    expect(sessions.users.size).toBe(0);
    expect(email.provider.codes).toHaveLength(0);

    const allowed = await server()
      .post('/auth/email/start')
      .set('Origin', ALLOWED_ORIGIN)
      .send({ email: mailbox, purpose: 'register', captchaToken: CAPTCHA_TOKEN });

    expect(allowed.status).toBe(202);
    expect(email.provider.lastCode(mailbox, 'register')).toBe(EMAIL_TEST_CODE);
  });

  it('answers 429 with a Retry-After header once the budget is spent', async () => {
    limits.deny(42);

    const response = await start();

    expect(response.status).toBe(429);
    expect(response.headers['retry-after']).toBe('42');
    expect(response.body).toEqual(genericError(429, 'Too Many Requests'));
    expect(email.provider.codes).toHaveLength(0);
  });

  it('marks every answer of the flow as uncacheable', async () => {
    const started = await start();
    const verified = await verify('register', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);

    const created = await signUp(verified.body.proof as string);
    const challenged = await signIn({ deviceKey: NEW_DEVICE_KEY });
    const refused = await signIn({ password: 'kestrel-harbor-quiet-92' });

    for (const response of [started, verified, created, challenged, refused]) {
      expect(response.headers['cache-control']).toBe('no-store');
    }
  });

  it('never echoes the address, the password or the code; only the proof comes back', async () => {
    const started = await start();
    const verified = await verify('register', EMAIL_TEST_CODE);
    const proof = verified.body.proof as string;
    const created = await signUp(proof);
    const challenged = await signIn({ deviceKey: NEW_DEVICE_KEY });
    const wrongCode = await verify('register', '000000');

    for (const response of [started, verified, created, challenged, wrongCode]) {
      const body = JSON.stringify(response.body);

      expect(body).not.toContain(mailbox);
      expect(body).not.toContain(PASSWORD);
      expect(body).not.toContain(EMAIL_TEST_CODE);
    }

    expect(Object.keys(verified.body)).toEqual(['proof']);
    expect(proof).not.toContain(mailbox);
    expect(proof).not.toContain(PASSWORD);
  });
});
