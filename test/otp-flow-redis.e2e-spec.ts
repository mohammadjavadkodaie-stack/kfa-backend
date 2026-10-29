import type { NestExpressApplication } from '@nestjs/platform-express';
import { Redis } from 'ioredis';
import request from 'supertest';
import { ProofTokenService, PROOF_NONCE_KEY_PREFIX } from '../src/auth/otp/proof-token';
import { OTP_VERIFY_IP_LIMIT, OTP_START_IP_LIMIT } from '../src/auth/otp/otp.service';
import {
  RATE_LIMIT_KEY_PREFIX,
  REDIS_CLIENT_OPTIONS,
} from '../src/rate-limit/redis-throttler.storage';
import { createTestApp } from './helpers/create-test-app';
import { applyTestEnv } from './helpers/test-env';

/**
 * Full OTP flow against a real Redis. Skipped unless `REDIS_URL_TEST` points at
 * a throwaway instance (see `docker-compose.dev.yml`):
 *
 *   REDIS_URL_TEST=redis://:dev-only-change-me@127.0.0.1:6380/0 pnpm test:e2e
 *
 * Point it at a THROWAWAY instance only: the suite flushes `kfa:rl:*` and
 * `kfa:otp:proof:*` keys between tests.
 */
const REDIS_URL = process.env.REDIS_URL_TEST;
const PHONE = '+14155552671';
const FORMATTED_PHONE = '+1 (415) 555-2671';
const WRONG_CODE = '000000';
const RIGHT_CODE = '123456';
const START_BODY = { phone: FORMATTED_PHONE, captchaToken: 'fake-captcha-pass' };

interface AuditRow {
  action: string;
  metadata: { phone?: string };
  ipHash: string | null;
  hash: string;
  createdAt: Date;
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

const describeWithRedis = REDIS_URL === undefined ? describe.skip : describe;

describeWithRedis('OTP flow (e2e)', () => {
  let app: NestExpressApplication;
  let admin: Redis;
  let rows: AuditRow[];

  beforeAll(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    admin = new Redis(REDIS_URL, REDIS_CLIENT_OPTIONS);
    await admin.ping();

    const auditPrisma = createAuditPrisma();
    rows = auditPrisma.rows;

    app = await createTestApp({ REDIS_URL }, { prisma: auditPrisma.prisma });
  });

  beforeEach(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    rows.length = 0;

    const keys = [
      ...(await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`)),
      ...(await admin.keys(`${PROOF_NONCE_KEY_PREFIX}*`)),
    ];

    if (keys.length > 0) {
      await admin.del(...keys);
    }
  });

  afterAll(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    await app.close();
    await admin.quit();
    // Do not leak the Redis override into the next suite in the same process.
    applyTestEnv();
  });

  const start = () => request(app.getHttpServer()).post('/auth/otp/start').send(START_BODY);
  const verify = (code: string) =>
    request(app.getHttpServer()).post('/auth/otp/verify').send({ phone: FORMATTED_PHONE, code });

  it('accepts a start request without revealing whether anything was sent', async () => {
    const response = await start();

    expect(response.status).toBe(202);
    expect(response.body).toEqual({ ok: true });
    expect(response.text).not.toContain(PHONE);
  });

  it('answers a resend inside the cooldown exactly like the first send', async () => {
    const first = await start();
    const second = await start();

    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);
  });

  it('issues a proof for the right code and burns it on first use', async () => {
    await start().expect(202);

    const rejected = await verify(WRONG_CODE);
    expect(rejected.status).toBe(400);
    expect(rejected.body).toEqual({ error: 'invalid_code' });

    const accepted = await verify(RIGHT_CODE);
    expect(accepted.status).toBe(200);
    expect(accepted.body).toEqual({ proof: expect.any(String) as string });

    const proof = (accepted.body as { proof: string }).proof;
    expect(proof.split('.')).toHaveLength(2);
    expect(proof).not.toContain(PHONE);
    expect(proof).not.toContain('4155552671');

    const proofTokens = app.get(ProofTokenService);

    await expect(proofTokens.verifyAndConsumeProof(proof)).resolves.toBe(PHONE);
    await expect(proofTokens.verifyAndConsumeProof(proof)).resolves.toBeNull();
  });

  it('keeps the nonce out of the raw phone space', async () => {
    await start().expect(202);
    await verify(RIGHT_CODE).expect(200);

    const keys = [
      ...(await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`)),
      ...(await admin.keys(`${PROOF_NONCE_KEY_PREFIX}*`)),
    ];

    expect(keys.length).toBeGreaterThan(0);

    for (const key of keys) {
      expect(key).not.toContain('4155552671');
    }
  });

  it('writes one masked audit row for a verified number', async () => {
    await start().expect(202);
    await verify(RIGHT_CODE).expect(200);

    expect(rows).toHaveLength(1);
    expect(rows[0]?.action).toBe('otp.verified');
    expect(rows[0]?.metadata).toEqual({ actor: 'system', phone: expect.any(String) as string });
    expect(rows[0]?.metadata.phone).not.toContain('5552671');
    expect(JSON.stringify(rows[0])).not.toContain(PHONE);
    expect(rows[0]?.ipHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('locks the phone after five wrong codes and audits it once', async () => {
    await start().expect(202);

    const bodies: unknown[] = [];

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await verify(WRONG_CODE);

      expect(response.status).toBe(400);
      bodies.push(response.body);
    }

    // Locked out: even the right code is refused, with the very same body.
    const locked = await verify(RIGHT_CODE);
    expect(locked.status).toBe(400);
    expect(locked.body).toEqual({ error: 'invalid_code' });
    expect(bodies).toEqual([locked.body, locked.body, locked.body, locked.body, locked.body]);
    expect(JSON.stringify(locked.body)).not.toContain('otp.locked');
    expect(locked.headers['retry-after']).toBeUndefined();

    expect(rows.map((row) => row.action)).toEqual(['otp.locked']);
  });

  it('rejects a failed captcha with the same generic envelope', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/otp/start')
      .send({ phone: PHONE, captchaToken: 'wrong-captcha' });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      statusCode: 400,
      message: 'Bad Request',
      requestId: expect.any(String) as string,
    });
    expect(response.text).not.toContain('captcha');
  });

  it('returns 429 with a Retry-After header once the IP send budget is spent', async () => {
    for (let attempt = 0; attempt < OTP_START_IP_LIMIT.limit; attempt += 1) {
      await start().expect(202);
    }

    const response = await start();

    expect(response.status).toBe(429);
    expect(response.body).toEqual({
      statusCode: 429,
      message: 'Too Many Requests',
      requestId: expect.any(String) as string,
    });
    expect(Number(response.headers['retry-after'])).toBeGreaterThan(0);
    expect(response.text).not.toContain('otp');
  });

  it('returns 429 once the IP verify budget is spent, after the phone lockout', async () => {
    await start().expect(202);

    for (let attempt = 0; attempt < OTP_VERIFY_IP_LIMIT.limit; attempt += 1) {
      await verify(WRONG_CODE).expect(400);
    }

    const response = await verify(RIGHT_CODE);

    expect(response.status).toBe(429);
    expect(Number(response.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('keeps both endpoints public and terse on malformed input', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/otp/verify')
      .send({ phone: PHONE, code: '12345' });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: 'invalid_code' });
  });
});
