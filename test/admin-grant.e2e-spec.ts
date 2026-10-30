import { randomUUID } from 'node:crypto';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { Role } from '../src/auth/roles';
import { InMemoryTotpRepository } from '../src/auth/totp/in-memory-totp.repository';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * Promotion to admin over HTTP, with no database and no Redis.
 *
 * What must hold: the route needs a staff session that stepped up, the policy
 * decides who may succeed, the promoted account loses every old token and finds
 * the second-factor gate closed until it enrols, and every refusal keeps the
 * shape the other admin routes already return.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;
const SECOND_FACTOR_REQUIRED = { ...FORBIDDEN, code: 'second_factor_required' } as const;

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

/** Same in-memory Prisma replacement as the moderation suite: real hashing, no rows. */
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

describe('Admin grant (e2e)', () => {
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
  const grantPath = (userId: string) => `/admin/users/${userId}/admin`;
  const rows = (action: string, targetId?: string) =>
    auditRows.filter(
      (row) => row.action === action && (targetId === undefined || row.targetId === targetId),
    );

  /** Registers through the real endpoint, then sets the role and the step-up. */
  async function signUp(role: Role, withStepUp = false): Promise<Account> {
    sequence += 1;
    const username = `grant_user_${sequence}`;
    const phone = `+1415777${String(3_000 + sequence).padStart(4, '0')}`;

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

  async function signIn(account: Account): Promise<string> {
    const response = await post('/auth/login', undefined, {
      proof: await proofs.issue(account.phone, 'login'),
    });

    expect(response.status).toBe(200);

    return (response.body as { accessToken: string }).accessToken;
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

  it('promotes a user when the owner stepped up', async () => {
    const owner = await signUp(Role.OWNER, true);
    const user = await signUp(Role.USER);

    const granted = await post(grantPath(user.userId), owner.token);

    expect(granted.status).toBe(204);
    expect(sessions.users.get(user.userId)?.role).toBe(Role.ADMIN);
    expect(rows('admin.admin.grant', user.userId).map((row) => row.metadata)).toEqual([
      { from: Role.USER, to: Role.ADMIN, notified: true },
    ]);
  });

  it('needs the second factor before the policy is asked', async () => {
    const owner = await signUp(Role.OWNER);
    const user = await signUp(Role.USER);

    const refused = await post(grantPath(user.userId), owner.token);

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
    expect(sessions.users.get(user.userId)?.role).toBe(Role.USER);
    expect(rows('admin.admin.grant', user.userId)).toHaveLength(0);
  });

  it('refuses an admin actor with the role refusal bytes', async () => {
    const admin = await signUp(Role.ADMIN, true);
    const member = await signUp(Role.USER);
    const user = await signUp(Role.USER);

    const asAdmin = await post(grantPath(user.userId), admin.token);
    const asMember = await post(grantPath(user.userId), member.token);

    expect(asAdmin.status).toBe(403);
    expect(asMember.status).toBe(403);
    expect(asAdmin.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    expect({ ...(asAdmin.body as object), requestId: '-' }).toEqual({
      ...(asMember.body as object),
      requestId: '-',
    });
    expect(sessions.users.get(user.userId)?.role).toBe(Role.USER);
    expect(rows('admin.admin.grant', user.userId)).toHaveLength(0);
  });

  it('cuts every old token and gates the new admin', async () => {
    const owner = await signUp(Role.OWNER, true);
    const user = await signUp(Role.USER);
    const secondToken = await signIn(user);

    expect((await get('/test/protected', user.token)).status).toBe(200);
    expect((await post(grantPath(user.userId), owner.token)).status).toBe(204);

    // The new role only applies to a session created after the promotion.
    expect((await get('/test/protected', user.token)).status).toBe(401);
    expect((await get('/test/protected', secondToken)).status).toBe(401);

    const fresh = await signIn(user);

    expect((await get('/test/protected', fresh)).status).toBe(403);
    expect((await get('/test/protected', fresh)).body).toEqual({
      ...SECOND_FACTOR_REQUIRED,
      requestId: expect.any(String),
    });

    // No credential yet, so the second factor is the one route that stays open.
    expect((await get('/auth/totp/status', fresh)).status).toBe(200);
  });

  it('refuses the owner and a blocked account with the same bytes', async () => {
    const owner = await signUp(Role.OWNER, true);
    const other = await signUp(Role.OWNER);
    const blocked = await signUp(Role.USER);

    expect((await post(`/admin/users/${blocked.userId}/block`, owner.token)).status).toBe(204);

    const asOwner = await post(grantPath(other.userId), owner.token);
    const asBlocked = await post(grantPath(blocked.userId), owner.token);
    const unknown = await post(grantPath(randomUUID()), owner.token);

    expect(asOwner.status).toBe(403);
    expect(asBlocked.status).toBe(403);
    expect({ ...(asOwner.body as object), requestId: '-' }).toEqual({
      ...(asBlocked.body as object),
      requestId: '-',
    });
    expect(unknown.status).toBe(404);
    expect({ ...(unknown.body as object), requestId: '-' }).toEqual({
      statusCode: 404,
      message: 'Not Found',
      requestId: '-',
    });

    expect(sessions.users.get(other.userId)?.role).toBe(Role.OWNER);
    expect(sessions.users.get(blocked.userId)?.role).toBe(Role.USER);
    expect(rows('admin.admin.grant', other.userId)).toHaveLength(0);
    expect(rows('admin.admin.grant', blocked.userId)).toHaveLength(0);
  });

  it('records one row for two concurrent grants', async () => {
    const owner = await signUp(Role.OWNER, true);
    const user = await signUp(Role.USER);

    const attempts = await Promise.all([
      post(grantPath(user.userId), owner.token),
      post(grantPath(user.userId), owner.token),
    ]);

    expect(attempts.map((attempt) => attempt.status)).toEqual([204, 204]);
    expect(sessions.users.get(user.userId)?.role).toBe(Role.ADMIN);
    expect(rows('admin.admin.grant', user.userId)).toHaveLength(1);
  });
});
