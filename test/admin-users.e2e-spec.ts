import { randomUUID } from 'node:crypto';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { STEPUP_WINDOW_MS } from '../src/auth/totp/step-up.guard';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * Block and unblock over HTTP, with no database and no Redis.
 *
 * What must hold: both routes need a staff role and a fresh second factor, a
 * block cuts every way back in, an unblock restores the login and nothing else,
 * and every refusal keeps the shape the other routes already return.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;
const SECOND_FACTOR_REQUIRED = { ...FORBIDDEN, code: 'second_factor_required' } as const;
const STEP_UP_REQUIRED = { ...FORBIDDEN, code: 'step_up_required' } as const;
const NOT_FOUND = { statusCode: 404, message: 'Not Found' } as const;

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

interface AuditRow {
  readonly action: string;
  readonly actorId: string | null;
  readonly targetId: string | null;
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

interface Account {
  readonly token: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly phone: string;
}

describe('Admin block and unblock (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let auditRows: AuditRow[];
  let sequence = 0;

  const server = () => request(app.getHttpServer());
  const post = (path: string, token?: string, body?: object) => {
    const call = server().post(path);
    const authorized = token === undefined ? call : call.set('Authorization', `Bearer ${token}`);

    return body === undefined ? authorized : authorized.send(body);
  };
  const get = (path: string, token: string) =>
    server().get(path).set('Authorization', `Bearer ${token}`);
  const rows = (action: string, targetId?: string) =>
    auditRows.filter(
      (row) => row.action === action && (targetId === undefined || row.targetId === targetId),
    );

  /** Registers through the real endpoint, then sets the role and the step-up. */
  async function signUp(role: Role, withStepUp = false): Promise<Account> {
    sequence += 1;
    const username = `moderation_user_${sequence}`;
    const phone = `+1415889${String(5_000 + sequence).padStart(4, '0')}`;

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

    // Staff sessions sit behind the second-factor gate; these fixtures start past it.
    if (withStepUp) await sessions.markStepUp(session.id, stored.id);

    return {
      token: (response.body as { accessToken: string }).accessToken,
      userId: stored.id,
      sessionId: session.id,
      phone,
    };
  }

  async function signIn(account: Account) {
    return post('/auth/login', undefined, { proof: await proofs.issue(account.phone, 'login') });
  }

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();

    const auditPrisma = createAuditPrisma();
    auditRows = auditPrisma.rows;

    app = await createTestApp(
      {},
      {
        prisma: auditPrisma.prisma,
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

  it('needs a second factor before the role is even checked', async () => {
    const admin = await signUp(Role.ADMIN);
    const user = await signUp(Role.USER);

    const refused = await post(`/admin/users/${user.userId}/block`, admin.token);

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
  });

  it('needs a step-up inside the window', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const user = await signUp(Role.USER);
    const session = sessions.sessions.get(admin.sessionId);

    if (session === undefined) throw new Error('admin session is missing');

    // Old enough that the staff gate is open but the action is not.
    session.stepupAt = new Date(Date.now() - STEPUP_WINDOW_MS - 1_000);

    const refused = await post(`/admin/users/${user.userId}/block`, admin.token);

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ ...STEP_UP_REQUIRED, requestId: expect.any(String) });
  });

  it('refuses USER and ATHLETE with the generic 403', async () => {
    const member = await signUp(Role.USER);
    const athlete = await signUp(Role.ATHLETE);
    const target = await signUp(Role.USER);
    const bodies: unknown[] = [];

    for (const account of [member, athlete]) {
      const refused = await post(`/admin/users/${target.userId}/block`, account.token);

      expect(refused.status).toBe(403);
      bodies.push({ ...(refused.body as object), requestId: '-' });
    }

    expect(bodies[0]).toEqual({ ...FORBIDDEN, requestId: '-' });
    expect(bodies[0]).toEqual(bodies[1]);
  });

  it('blocks an account and cuts every way back in', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const user = await signUp(Role.USER);
    const second = await signIn(user);

    expect(second.status).toBe(200);

    const blocked = await post(`/admin/users/${user.userId}/block`, admin.token);

    expect(blocked.status).toBe(204);
    expect((await get('/test/protected', user.token)).status).toBe(401);
    expect(
      (await get('/test/protected', (second.body as { accessToken: string }).accessToken)).status,
    ).toBe(401);

    const denied = await signIn(user);
    const unknownNumber = await post('/auth/login', undefined, {
      proof: await proofs.issue('+14150000000', 'login'),
    });

    // Already true before this feature: the auth contract collapses every
    // credential rejection into one shape, so a block leaks no new signal.
    expect(denied.status).toBe(401);
    expect(denied.body).toEqual({ error: 'invalid_credentials' });
    expect(denied.body).toEqual(unknownNumber.body);

    expect(rows('admin.user.block', user.userId)).toHaveLength(1);
  });

  it('answers a repeated block the same way and records once', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const user = await signUp(Role.USER);

    expect((await post(`/admin/users/${user.userId}/block`, admin.token)).status).toBe(204);
    expect((await post(`/admin/users/${user.userId}/block`, admin.token)).status).toBe(204);
    expect(rows('admin.user.block', user.userId)).toHaveLength(1);
  });

  it('unblocks and lets the account sign in again', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const user = await signUp(Role.USER);

    expect((await post(`/admin/users/${user.userId}/block`, admin.token)).status).toBe(204);

    const unblocked = await post(`/admin/users/${user.userId}/unblock`, admin.token);

    expect(unblocked.status).toBe(204);
    expect(rows('admin.user.unblock', user.userId)).toHaveLength(1);

    const fresh = await signIn(user);

    expect(fresh.status).toBe(200);

    const token = (fresh.body as { accessToken: string }).accessToken;

    expect((await get('/test/protected', token)).status).toBe(200);

    // Repeating the unblock changes nothing and records nothing.
    expect((await post(`/admin/users/${user.userId}/unblock`, admin.token)).status).toBe(204);
    expect(rows('admin.user.unblock', user.userId)).toHaveLength(1);
  });

  it('refuses the owner and oneself with the same bytes', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const owner = await signUp(Role.OWNER);

    const ownerAttempt = await post(`/admin/users/${owner.userId}/block`, admin.token);
    const selfAttempt = await post(`/admin/users/${admin.userId}/block`, admin.token);

    expect(ownerAttempt.status).toBe(403);
    expect(selfAttempt.status).toBe(403);
    expect(ownerAttempt.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    expect({ ...(ownerAttempt.body as object), requestId: '-' }).toEqual({
      ...(selfAttempt.body as object),
      requestId: '-',
    });

    // The owner row and the actor are untouched.
    expect(sessions.users.get(owner.userId)?.status).toBe('ACTIVE');
    expect(sessions.users.get(admin.userId)?.status).toBe('ACTIVE');
    expect(rows('admin.user.block', owner.userId)).toHaveLength(0);
  });

  it('answers a malformed id exactly like an unknown one', async () => {
    const admin = await signUp(Role.ADMIN, true);

    const unknown = await post(`/admin/users/${randomUUID()}/block`, admin.token);
    const malformed = await post('/admin/users/not-a-uuid/block', admin.token);

    expect(unknown.status).toBe(404);
    expect(unknown.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    expect({ ...(unknown.body as object), requestId: '-' }).toEqual({
      ...(malformed.body as object),
      requestId: '-',
    });
  });
});
