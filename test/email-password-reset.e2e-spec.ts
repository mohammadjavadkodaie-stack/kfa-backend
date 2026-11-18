import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { EmailProofService } from '../src/auth/email/email-proof';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { REFRESH_COOKIE_NAME } from '../src/auth/token/refresh-token';
import type { RateLimitService } from '../src/rate-limit/rate-limit.service';
import { FakeRateLimit } from './helpers/auth-service-harness';
import { createTestApp } from './helpers/create-test-app';
import { EMAIL_TEST_CODE, createEmailHarness, type EmailHarness } from './helpers/email-harness';
import { InMemoryProofNonceStore } from './helpers/proof-nonce-store';

/**
 * The password reset flow over HTTP: `POST /auth/password/reset/start`,
 * `POST /auth/email/verify` with `purpose: 'password_reset'` and
 * `POST /auth/password/reset`.
 *
 * What matters here is what the flow refuses to say. The start step must not tell
 * a stranger whether an address has an account, the finish step must not tell a
 * caller whether a proof was malformed, spent or issued for another purpose, and
 * no answer may carry the address, the password, the mailed code or a session.
 * Every dependency outside the process is replaced: sessions, codes, nonces,
 * transport, limiter and audit store live in memory.
 */

const CAPTCHA_TOKEN = 'fake-captcha-pass';
/** Long enough for the policy, and unrelated to the address or the username. */
const PASSWORD = 'kestrel-harbor-quiet-91';
const NEW_PASSWORD = 'lantern-meadow-brisk-42';
const THIRD_PASSWORD = 'harbor-amber-silent-63';
const DEVICE_KEY = 'device-alpha';
const NEW_DEVICE_KEY = 'device-beta';
const ALLOWED_ORIGIN = 'http://localhost:3000';
const FOREIGN_ORIGIN = 'https://evil.example';
const INVALID_CODE = { error: 'invalid_code' };
const INVALID_PROOF = { error: 'invalid_proof' };
const GENERIC_UNAUTHORIZED = { error: 'invalid_credentials' };
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
 * and redaction logic, the rows just never leave the process.
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

/**
 * Nonce store stand-in. Unlike the register suite's store this one also answers
 * the non-consuming read: the reset verifies the proof before it spends it.
 */
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

describe('Password reset HTTP contract (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let limits: FakeRateLimit;
  let nonces: InMemoryProofNonceStore;
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
      .post('/auth/password/reset/start')
      .send({ email: address, captchaToken: CAPTCHA_TOKEN });

  const verify = (
    purpose: 'register' | 'login_device' | 'password_reset',
    code: string,
    address: string = mailbox,
  ) => server().post('/auth/email/verify').send({ email: address, purpose, code });

  const reset = (proof: string, newPassword: string = NEW_PASSWORD) =>
    server().post('/auth/password/reset').send({ proof, newPassword });

  const signIn = (
    options: { email?: string; password?: string; deviceKey?: string | null; proof?: string } = {},
  ) => {
    // `null` means the header is absent, which is what a first-time client sends.
    const deviceKey = options.deviceKey === undefined ? DEVICE_KEY : options.deviceKey;
    const pending = server()
      .post('/auth/signin')
      .send({
        email: options.email ?? mailbox,
        password: options.password ?? PASSWORD,
        deviceName: 'Phone',
        ...(options.proof === undefined ? {} : { proof: options.proof }),
      });

    return deviceKey === null ? pending : pending.set('X-Device-Key', deviceKey);
  };

  /** Registration as a client performs it: start, verify, signup on one device. */
  const registerAccount = async (): Promise<request.Response> => {
    const started = await server()
      .post('/auth/email/start')
      .send({ email: mailbox, purpose: 'register', captchaToken: CAPTCHA_TOKEN });

    expect(started.status).toBe(202);

    const verified = await verify('register', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);

    const created = await server()
      .post('/auth/signup')
      .set('X-Device-Key', DEVICE_KEY)
      .send({
        proof: verified.body.proof as string,
        username,
        password: PASSWORD,
        deviceName: 'Laptop',
      });

    expect(created.status).toBe(200);
    expect(refreshCookie(created)).not.toBeNull();

    return created;
  };

  /** The proof the owner gets by asking for a code and typing it back. */
  const resetProof = async (address: string = mailbox): Promise<string> => {
    const started = await start(address);

    expect(started.status).toBe(202);
    expect(email.provider.lastCode(address, 'password_reset')).toBe(EMAIL_TEST_CODE);

    const verified = await verify('password_reset', EMAIL_TEST_CODE, address);

    expect(verified.status).toBe(200);

    return verified.body.proof as string;
  };

  /** The proof a challenged client gets by typing the mailed login code. */
  const loginProof = async (): Promise<string> => {
    const verified = await verify('login_device', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);

    return verified.body.proof as string;
  };

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    limits = new FakeRateLimit();
    nonces = new InMemoryProofNonceStore();
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

  it('resets the password over email: the old one stops working, the new one signs in, nothing is handed back', async () => {
    const created = await registerAccount();
    const oldCookie = refreshCookie(created) as string;

    const started = await start();

    expect(started.status).toBe(202);
    expect(started.body).toEqual({ ok: true });
    expect(started.headers['cache-control']).toBe('no-store');
    expect(email.provider.lastCode(mailbox, 'password_reset')).toBe(EMAIL_TEST_CODE);

    const verified = await verify('password_reset', EMAIL_TEST_CODE);

    expect(verified.status).toBe(200);
    expect(Object.keys(verified.body)).toEqual(['proof']);

    const finished = await reset(verified.body.proof as string);

    expect(finished.status).toBe(204);
    expect(finished.text).toBe('');
    expect(finished.headers['cache-control']).toBe('no-store');
    expect(refreshCookie(finished)).toBeNull();

    // The old password no longer opens the account.
    const oldPassword = await signIn({ password: PASSWORD });

    expect(oldPassword.status).toBe(401);
    expect(oldPassword.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(refreshCookie(oldPassword)).toBeNull();

    // The session that existed before the reset is dead.
    const staleRefresh = await server()
      .post('/auth/refresh')
      .set('Cookie', oldCookie)
      .set('X-Device-Key', DEVICE_KEY);

    expect(staleRefresh.status).toBe(401);

    // The new password is accepted; the revocation made every device unknown,
    // so the sign-in first proves the password with a mailed challenge.
    const challenge = await signIn({ password: NEW_PASSWORD });

    expect(challenge.status).toBe(403);
    expect(challenge.body).toEqual(DEVICE_REQUIRED);
    expect(email.provider.lastCode(mailbox, 'login_device')).toBe(EMAIL_TEST_CODE);

    const signedIn = await signIn({ password: NEW_PASSWORD, proof: await loginProof() });

    expect(signedIn.status).toBe(200);
    expect(refreshCookie(signedIn)).not.toBeNull();
  });

  it('answers the same 202 for an existing and an unknown address, and mails only the existing one', async () => {
    await registerAccount();
    email.provider.clear();

    const existing = await start();
    const unknown = await start(otherMailbox);

    expect(existing.status).toBe(202);
    expect(unknown.status).toBe(202);
    expect(unknown.body).toEqual(existing.body);
    expect(unknown.headers['cache-control']).toBe(existing.headers['cache-control']);
    expect(email.provider.codesFor(mailbox, 'password_reset')).toEqual([EMAIL_TEST_CODE]);
    expect(email.provider.codesFor(otherMailbox, 'password_reset')).toEqual([]);
  });

  it('refuses malformed bodies with the generic 400 envelope', async () => {
    const refused = [
      await server().post('/auth/password/reset/start').send({ email: mailbox }),
      await server()
        .post('/auth/password/reset/start')
        .send({ email: 'not-an-address', captchaToken: CAPTCHA_TOKEN }),
      await server()
        .post('/auth/password/reset/start')
        .send({ email: mailbox, captchaToken: CAPTCHA_TOKEN, extra: true }),
      await server().post('/auth/password/reset').send({ proof: 'p' }),
      await server()
        .post('/auth/password/reset')
        .send({ proof: 'p', newPassword: NEW_PASSWORD, email: mailbox }),
      await server().post('/auth/password/reset').send({ proof: 'p', newPassword: '' }),
    ];

    for (const response of refused) {
      expect(response.status).toBe(400);
      expect(response.body).toEqual(genericError(400, 'Bad Request'));
    }

    expect(email.provider.codes).toHaveLength(0);
  });

  it('refuses a bad captcha token at the start step without mailing anything', async () => {
    await registerAccount();
    email.provider.clear();

    const response = await server()
      .post('/auth/password/reset/start')
      .send({ email: mailbox, captchaToken: 'definitely-not-a-token' });

    expect(response.status).toBe(400);
    expect(response.body).toEqual(genericError(400, 'Bad Request'));
    expect(email.provider.codes).toHaveLength(0);
  });

  it('refuses a weak password with its reason and leaves the proof usable', async () => {
    await registerAccount();
    const proof = await resetProof();

    const tooShort = await reset(proof, 'short');
    const identity = await reset(proof, `${username}-Zaphod-${username}`);

    expect(tooShort.status).toBe(400);
    expect(tooShort.body).toEqual({ error: 'weak_password', reason: 'too_short' });
    expect(identity.status).toBe(400);
    expect(identity.body).toEqual({ error: 'weak_password', reason: 'contains_identity' });

    // Neither refusal spent the proof: the same token still resets.
    const finished = await reset(proof);

    expect(finished.status).toBe(204);

    const old = await signIn({ password: PASSWORD });

    expect(old.status).toBe(401);
  });

  it('spends the proof exactly once', async () => {
    await registerAccount();
    const proof = await resetProof();

    expect((await reset(proof)).status).toBe(204);

    const reused = await reset(proof, THIRD_PASSWORD);

    expect(reused.status).toBe(401);
    expect(reused.body).toEqual(INVALID_PROOF);
    expect(auditRows.filter((row) => row.action === 'password.reset')).toHaveLength(1);
  });

  it('rejects a proof that was issued for the register purpose', async () => {
    await registerAccount();

    const registerProof = await proofs.issueEmailProof({ email: mailbox, purpose: 'register' });
    const response = await reset(registerProof);

    expect(response.status).toBe(401);
    expect(response.body).toEqual(INVALID_PROOF);
    expect(auditRows.filter((row) => row.action === 'password.reset')).toHaveLength(0);
  });

  it('writes one password.reset row with a masked address and never echoes a secret', async () => {
    await registerAccount();
    email.provider.clear();

    const started = await start();
    const verified = await verify('password_reset', EMAIL_TEST_CODE);
    const finished = await reset(verified.body.proof as string);

    const rows = auditRows.filter((row) => row.action === 'password.reset');

    expect(rows).toHaveLength(1);

    // The trail carries the mask, never the address or a password.
    const trail = JSON.stringify(auditRows);

    expect(trail).not.toContain(mailbox);
    expect(trail).not.toContain(PASSWORD);
    expect(trail).not.toContain(NEW_PASSWORD);

    for (const response of [started, verified, finished]) {
      expect(response.headers['cache-control']).toBe('no-store');

      const body = JSON.stringify(response.body);

      expect(body).not.toContain(mailbox);
      expect(body).not.toContain(PASSWORD);
      expect(body).not.toContain(NEW_PASSWORD);
      expect(body).not.toContain(EMAIL_TEST_CODE);
    }

    expect(Object.keys(verified.body)).toEqual(['proof']);
    expect(JSON.stringify(rows[0]?.metadata)).toContain('[REDACTED]');
  });

  it('notifies the owner once, without a code or a password in the message', async () => {
    await registerAccount();
    email.provider.clear();

    expect((await reset(await resetProof())).status).toBe(204);

    expect(email.provider.notices).toHaveLength(1);

    const notice = email.provider.notices[0];

    expect(notice?.to).toBe(mailbox);
    expect(notice?.kind).toBe('password_changed');

    const serialized = JSON.stringify(notice);

    expect(serialized).not.toContain(EMAIL_TEST_CODE);
    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain(NEW_PASSWORD);
  });

  it('keeps the reset when the notice cannot be delivered', async () => {
    await registerAccount();
    const proof = await resetProof();
    const provider = email.provider;
    const original = provider.sendNotice.bind(provider);

    provider.sendNotice = () => Promise.reject(new Error('smtp down'));

    try {
      const finished = await reset(proof);

      expect(finished.status).toBe(204);
    } finally {
      provider.sendNotice = original;
    }

    // The change stands: the old password is dead, the new one proves itself.
    const old = await signIn({ password: PASSWORD });

    expect(old.status).toBe(401);

    const challenge = await signIn({ password: NEW_PASSWORD });

    expect(challenge.status).toBe(403);

    const signedIn = await signIn({ password: NEW_PASSWORD, proof: await loginProof() });

    expect(signedIn.status).toBe(200);
    expect(auditRows.map((row) => row.action)).toContain('password.reset');
  });

  it('resets a blocked account, and the block still holds at sign-in', async () => {
    await registerAccount();

    const account = [...sessions.users.values()].find((user) => user.email === mailbox);

    expect(account).toBeDefined();
    if (account !== undefined) account.status = 'BLOCKED';

    expect((await reset(await resetProof())).status).toBe(204);

    const refused = await signIn({ password: NEW_PASSWORD });

    expect(refused.status).toBe(401);
    expect(refused.body).toEqual(GENERIC_UNAUTHORIZED);
    expect(refreshCookie(refused)).toBeNull();
  });

  it('locks the reset code after the attempt budget, even for the right code', async () => {
    await registerAccount();
    await start();

    const maxAttempts = Number(process.env.EMAIL_CODE_MAX_ATTEMPTS ?? 5);
    const attempts = [];

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      attempts.push(await verify('password_reset', '000000'));
    }

    for (const attempt of attempts) {
      expect(attempt.status).toBe(400);
      expect(attempt.body).toEqual(INVALID_CODE);
    }

    const lockedOut = await verify('password_reset', EMAIL_TEST_CODE);

    expect(lockedOut.status).toBe(400);
    expect(lockedOut.body).toEqual(INVALID_CODE);
    expect(auditRows.map((row) => row.action)).toContain('email_code.locked');
  });

  it('answers 429 with a Retry-After header on both reset routes once the budget is spent', async () => {
    limits.deny(42);

    const started = await start();

    expect(started.status).toBe(429);
    expect(started.headers['retry-after']).toBe('42');
    expect(started.body).toEqual(genericError(429, 'Too Many Requests'));
    expect(email.provider.codes).toHaveLength(0);

    const finished = await reset('not-a-proof');

    expect(finished.status).toBe(429);
    expect(finished.headers['retry-after']).toBe('42');
    expect(finished.body).toEqual(genericError(429, 'Too Many Requests'));
  });

  it('refuses a foreign origin and a cross-site fetch on both reset routes', async () => {
    await registerAccount();
    email.provider.clear();

    const refused = [
      await server()
        .post('/auth/password/reset/start')
        .set('Origin', FOREIGN_ORIGIN)
        .send({ email: mailbox, captchaToken: CAPTCHA_TOKEN }),
      await server()
        .post('/auth/password/reset/start')
        .set('Sec-Fetch-Site', 'cross-site')
        .send({ email: mailbox, captchaToken: CAPTCHA_TOKEN }),
      await server()
        .post('/auth/password/reset')
        .set('Origin', FOREIGN_ORIGIN)
        .send({ proof: 'p', newPassword: NEW_PASSWORD }),
      await server()
        .post('/auth/password/reset')
        .set('Sec-Fetch-Site', 'cross-site')
        .send({ proof: 'p', newPassword: NEW_PASSWORD }),
    ];

    for (const response of refused) {
      expect(response.status).toBe(403);
      expect(response.body).toEqual(genericError(403, 'Forbidden'));
    }

    expect(email.provider.codes).toHaveLength(0);

    // The same call from an allowlisted origin goes through.
    const allowed = await server()
      .post('/auth/password/reset/start')
      .set('Origin', ALLOWED_ORIGIN)
      .send({ email: mailbox, captchaToken: CAPTCHA_TOKEN });

    expect(allowed.status).toBe(202);
    expect(email.provider.lastCode(mailbox, 'password_reset')).toBe(EMAIL_TEST_CODE);
  });

  it('answers 202 but sends nothing on an immediate resend', async () => {
    await registerAccount();
    email.provider.clear();

    expect((await start()).status).toBe(202);

    const again = await start();

    expect(again.status).toBe(202);
    expect(again.body).toEqual({ ok: true });
    expect(email.provider.codesFor(mailbox, 'password_reset')).toHaveLength(1);
  });

  it('revokes the sessions created after an earlier reset when the owner resets again', async () => {
    await registerAccount();

    expect((await reset(await resetProof())).status).toBe(204);

    // Sign back in with the new password through the device challenge.
    const challenge = await signIn({ password: NEW_PASSWORD });

    expect(challenge.status).toBe(403);

    const signedIn = await signIn({ password: NEW_PASSWORD, proof: await loginProof() });

    expect(signedIn.status).toBe(200);

    const liveCookie = refreshCookie(signedIn) as string;

    // A fresh proof, as if the owner had asked for another code later on.
    const secondProof = await proofs.issueEmailProof({ email: mailbox, purpose: 'password_reset' });

    expect((await reset(secondProof, THIRD_PASSWORD)).status).toBe(204);

    const stale = await server()
      .post('/auth/refresh')
      .set('Cookie', liveCookie)
      .set('X-Device-Key', DEVICE_KEY);

    expect(stale.status).toBe(401);

    // The password from the first reset is gone, the newest one is accepted.
    const previous = await signIn({ password: NEW_PASSWORD });

    expect(previous.status).toBe(401);

    const current = await signIn({ password: THIRD_PASSWORD });

    expect(current.status).toBe(403);
    expect(current.body).toEqual(DEVICE_REQUIRED);
  });
});
