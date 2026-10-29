import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * Phone change over HTTP with no database, no Redis and no SMS provider.
 *
 * What is under test is the contract a client sees: the four steps, the single
 * rejection body, the fact that the asking session survives, and that the
 * anonymous OTP endpoints cannot mint a phone-change proof.
 */

const PHONE = '+14155552671';
const NEW_PHONE = '+14155559999';
const TAKEN_PHONE = '+14155558888';
const USERNAME = 'mira';
const CAPTCHA = 'fake-captcha-pass';
const CODE = '123456';

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

/** Explicit limiter with a switch, so a suite never depends on Redis windows. */
class OpenRateLimit {
  allowed = true;

  async consume(): Promise<RateLimitDecision> {
    return { allowed: this.allowed, remaining: 99, retryAfterSeconds: this.allowed ? 0 : 30 };
  }

  async reset(): Promise<void> {}
}

interface AuditRow {
  readonly action: string;
  readonly metadata: { phone?: string };
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

const bearer = (accessToken: string): Record<string, string> => ({
  Authorization: `Bearer ${accessToken}`,
});

const GENERIC_UNAUTHORIZED = {
  statusCode: 401,
  message: 'Unauthorized',
  requestId: expect.any(String) as string,
};

describe('Phone change over HTTP (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let limiter: OpenRateLimit;
  let rows: AuditRow[];

  const server = () => request(app.getHttpServer());

  const register = async (username: string = USERNAME, phone: string = PHONE) => {
    const response = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

    expect(response.status).toBe(200);

    return response;
  };

  const accessTokenOf = (response: request.Response): string =>
    (response.body as { accessToken: string }).accessToken;

  const start = (accessToken: string, phone: string) =>
    server()
      .post('/auth/phone-change/start')
      .set(bearer(accessToken))
      .send({ phone, captchaToken: CAPTCHA });

  const verifyNew = (accessToken: string, phone: string, code: string = CODE) =>
    server().post('/auth/phone-change/verify-new').set(bearer(accessToken)).send({ phone, code });

  const verifyOld = (accessToken: string, code: string = CODE) =>
    server().post('/auth/phone-change/verify-old').set(bearer(accessToken)).send({ code });

  const confirm = (accessToken: string, body: object) =>
    server().post('/auth/phone-change/confirm').set(bearer(accessToken)).send(body);

  const proofOf = (response: request.Response): string => {
    expect(response.status).toBe(200);

    return (response.body as { proof: string }).proof;
  };

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    limiter = new OpenRateLimit();

    const auditPrisma = createAuditPrisma();
    rows = auditPrisma.rows;

    app = await createTestApp(
      {},
      {
        prisma: auditPrisma.prisma,
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
    sessions.revokedSessions.length = 0;
    rows.length = 0;
    limiter.allowed = true;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('access control', () => {
    it('refuses every phone-change route without an access token', async () => {
      const responses = [
        await server().post('/auth/phone-change/start').send({ phone: NEW_PHONE }),
        await server().post('/auth/phone-change/verify-new').send({ phone: NEW_PHONE }),
        await server().post('/auth/phone-change/verify-old').send({ code: CODE }),
        await server().post('/auth/phone-change/confirm').send({}),
      ];

      for (const response of responses) {
        expect(response.status).toBe(401);
        expect(response.body).toEqual(GENERIC_UNAUTHORIZED);
      }
    });

    it('refuses a cross-site origin on every step', async () => {
      const created = accessTokenOf(await register());
      const headers = { ...bearer(created), Origin: 'https://evil.example' };
      const responses = [
        await server().post('/auth/phone-change/start').set(headers).send({}),
        await server().post('/auth/phone-change/verify-new').set(headers).send({}),
        await server().post('/auth/phone-change/verify-old').set(headers).send({}),
        await server().post('/auth/phone-change/confirm').set(headers).send({}),
      ];

      for (const response of responses) expect(response.status).toBe(403);
    });

    it('never lets an anonymous caller ask for a phone-change purpose', async () => {
      const started = await server()
        .post('/auth/otp/start')
        .send({ phone: NEW_PHONE, purpose: 'phone_change_new', captchaToken: CAPTCHA });
      const verified = await server()
        .post('/auth/otp/verify')
        .send({ phone: NEW_PHONE, code: CODE, purpose: 'phone_change_old' });

      expect(started.status).toBe(400);
      expect(verified.status).toBe(400);
      expect(started.body).not.toHaveProperty('ok');
      expect(verified.body).not.toHaveProperty('proof');
    });
  });

  describe('POST /auth/phone-change/start', () => {
    it('answers a taken number exactly like a free one', async () => {
      const created = accessTokenOf(await register());
      await register('someone_else', TAKEN_PHONE);

      const taken = await start(created, TAKEN_PHONE);
      const free = await start(created, NEW_PHONE);

      expect(taken.status).toBe(202);
      expect(taken.body).toEqual({ ok: true });
      expect(free.body).toEqual(taken.body);
    });

    it('refuses a body the flow did not define', async () => {
      const created = accessTokenOf(await register());

      const response = await server()
        .post('/auth/phone-change/start')
        .set(bearer(created))
        .send({ phone: NEW_PHONE, captchaToken: CAPTCHA, purpose: 'phone_change_old' });

      expect(response.status).toBe(400);
    });
  });

  describe('POST /auth/phone-change/verify-*', () => {
    it('answers a wrong code with one generic body', async () => {
      const created = accessTokenOf(await register());
      await start(created, NEW_PHONE);

      const wrongNew = await verifyNew(created, NEW_PHONE, '000000');
      const wrongOld = await verifyOld(created, '000000');

      expect(wrongNew.status).toBe(400);
      expect(wrongNew.body).toEqual({ error: 'invalid_code' });
      expect(wrongOld.body).toEqual(wrongNew.body);
    });
  });

  describe('POST /auth/phone-change/confirm', () => {
    it('moves the account over the four steps and keeps the asking session', async () => {
      const created = accessTokenOf(await register());

      expect((await start(created, NEW_PHONE)).status).toBe(202);

      const proofNew = proofOf(await verifyNew(created, NEW_PHONE));
      const proofOld = proofOf(await verifyOld(created));

      const response = await confirm(created, { proofNew, proofOld });

      expect(response.status).toBe(204);
      expect(response.text).toBe('');
      expect([...sessions.users.values()].map((user) => user.phone)).toEqual([NEW_PHONE]);

      // The session that asked survives; the phone is the only thing that moved.
      expect((await server().get('/auth/sessions').set(bearer(created))).status).toBe(200);

      const actions = rows.map((row) => row.action);

      expect(actions).toContain('auth.phone_change.started');
      expect(actions).toContain('auth.phone_changed');
      expect(JSON.stringify(rows)).not.toContain(NEW_PHONE);
    });

    it('answers a proof from another purpose with the same generic rejection', async () => {
      const created = accessTokenOf(await register());
      await start(created, NEW_PHONE);

      const proofNew = proofOf(await verifyNew(created, NEW_PHONE));
      const proofOld = proofOf(await verifyOld(created));
      const foreign = await proofs.issue(PHONE, 'register');

      const crossed = await confirm(created, { proofNew: foreign, proofOld });
      const replayed = await confirm(created, { proofNew, proofOld });
      const empty = await confirm(created, {});

      expect(crossed.status).toBe(400);
      expect(crossed.body).toEqual({ error: 'phone_change_rejected' });
      expect(replayed.body).toEqual(crossed.body);
      expect(empty.body).toEqual(crossed.body);
      // Nothing moved, so a stolen proof set is not a way in.
      expect([...sessions.users.values()].map((user) => user.phone)).toEqual([PHONE]);
    });
  });
});
