import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { AccessAction } from '../src/auth/policy/access-policy';
import { Role } from '../src/auth/roles';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';

/**
 * The access policy and its audit event over HTTP, with no database and no
 * Redis. Roles are changed in the in-memory store the way an admin would, so a
 * spec can replay the very same access token against a changed account.
 *
 * What must hold:
 * - a refusal is the same generic 403 the guards return, with no reason in it,
 * - one `authz.denied` row is written for a refused ADMIN or OWNER action,
 * - an allowed action writes nothing and answers 204,
 * - the actor's role is read from storage on every request.
 */

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
  readonly actorRole: string | null;
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

describe('Access policy and authz.denied (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let auditRows: AuditRow[];
  let sequence = 0;

  const server = () => request(app.getHttpServer());
  const denials = () => auditRows.filter((row) => row.action === 'authz.denied');

  /** Registers a fresh account through the real endpoint, then sets its role. */
  async function signUp(role: Role): Promise<{ token: string; userId: string }> {
    sequence += 1;
    const username = `policy_user_${sequence}`;
    const phone = `+1415555${String(4_000 + sequence).padStart(4, '0')}`;

    const response = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

    expect(response.status).toBe(200);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`user ${username} was not stored`);

    sessions.setUserRole(stored.id, { role });

    return { token: (response.body as { accessToken: string }).accessToken, userId: stored.id };
  }

  const authorize = (
    token: string,
    body: { targetId: string; action: AccessAction; role?: Role },
  ) => server().post('/test/authorize').set('Authorization', `Bearer ${token}`).send(body);

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

  it('refuses an ADMIN blocking the OWNER and records exactly one attempt', async () => {
    const actor = await signUp(Role.ADMIN);
    const owner = await signUp(Role.OWNER);

    const response = await authorize(actor.token, {
      targetId: owner.userId,
      action: AccessAction.USER_BLOCK,
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    expect(JSON.stringify(response.body)).not.toContain('target_is_owner');

    expect(denials()).toHaveLength(1);

    const [row] = denials();

    expect(row?.actorId).toBe(actor.userId);
    expect(row?.actorRole).toBe('ADMIN');
    expect(row?.targetId).toBe(owner.userId);
    expect(row?.metadata).toEqual({
      actorRole: 'ADMIN',
      action: 'user.block',
      targetId: owner.userId,
      targetRole: 'OWNER',
    });
  });

  it('refuses an ADMIN granting ADMIN to another ADMIN, with the same 403', async () => {
    const actor = await signUp(Role.ADMIN);
    const peer = await signUp(Role.ADMIN);

    const response = await authorize(actor.token, {
      targetId: peer.userId,
      action: AccessAction.ADMIN_GRANT,
    });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });

    const recorded = denials();

    expect(recorded).toHaveLength(2);
    expect(recorded[1]?.metadata).toEqual({
      actorRole: 'ADMIN',
      action: 'admin.grant',
      targetId: peer.userId,
      targetRole: 'ADMIN',
    });
  });

  it('lets the OWNER block and re-role a regular account without an audit entry', async () => {
    const owner = await signUp(Role.OWNER);
    const user = await signUp(Role.USER);

    await authorize(owner.token, {
      targetId: user.userId,
      action: AccessAction.USER_BLOCK,
    }).expect(204);
    await authorize(owner.token, {
      targetId: user.userId,
      action: AccessAction.USER_CHANGE_ROLE,
      role: Role.ATHLETE,
    }).expect(204);

    expect(denials()).toHaveLength(2);
  });

  it('takes the actor role from the database, not from the token', async () => {
    const owner = await signUp(Role.OWNER);
    const admin = await signUp(Role.ADMIN);

    await authorize(owner.token, {
      targetId: admin.userId,
      action: AccessAction.USER_BLOCK,
    }).expect(204);

    // Demoted in storage only; the token still says nothing about the role.
    sessions.setUserRole(owner.userId, { role: Role.USER });

    const refused = await authorize(owner.token, {
      targetId: admin.userId,
      action: AccessAction.USER_BLOCK,
    });

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });

    // A refused USER actor is not audited: the roles guard owns that case.
    expect(denials()).toHaveLength(2);
  });
});
