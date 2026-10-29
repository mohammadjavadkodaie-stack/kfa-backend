import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * The rotation race against a real PostgreSQL: only the single-statement
 * consume can guarantee that one of two parallel refreshes wins. Point
 * `DATABASE_URL_TEST` at a throwaway database to run it.
 */

const hash = () => randomBytes(32).toString('hex');
const seconds = (value: number) => value * 1_000;

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '7')
    .slice(0, 7)}`;
}

function username(): string {
  return `rot_${randomUUID().replaceAll('-', '')}`.slice(0, 30);
}

describeWithDatabase('auth session rotation (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let sessions: PrismaSessionRepository;
  let userId: string;
  let sessionId: string;
  let refreshTokenHash: string;

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    sessions = new PrismaSessionRepository(prisma as unknown as PrismaService);

    const now = new Date();
    userId = randomUUID();
    refreshTokenHash = hash();

    const created = await sessions.createAccount({
      userId,
      phone: phone(),
      username: username(),
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: 'jest',
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(60 * 60 * 24 * 30)),
      refreshTokenHash,
      refreshExpiresAt: new Date(now.getTime() + seconds(60 * 60 * 24 * 14)),
    });

    if (created === null) throw new Error('could not seed an account');

    sessionId = created.sessionId;
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: userId } });
      await prisma.$disconnect();
    }
  });

  it('lets exactly one of two parallel rotations consume the token', async () => {
    const now = new Date();
    const rotate = (nextTokenHash: string) =>
      sessions.rotateRefreshToken({
        tokenHash: refreshTokenHash,
        nextTokenHash,
        now,
        refreshTtlMs: seconds(60 * 60 * 24 * 14),
      });

    const results = await Promise.all([rotate(hash()), rotate(hash())]);
    const outcomes = results.map((result) => result.outcome).sort();

    expect(outcomes).toEqual(['reused', 'rotated']);

    const winner = results.find((result) => result.outcome === 'rotated');
    const loser = results.find((result) => result.outcome === 'reused');

    expect(winner).toMatchObject({ userId, sessionId, userStatus: 'ACTIVE' });
    expect(loser).toEqual({ outcome: 'reused', userId });

    const stored = await prisma.refreshToken.findMany({ where: { sessionId } });
    expect(stored).toHaveLength(2);
    expect(stored.filter((token) => token.usedAt !== null)).toHaveLength(1);
  });

  it('treats an unknown or expired token as unknown', async () => {
    await expect(
      sessions.rotateRefreshToken({
        tokenHash: hash(),
        nextTokenHash: hash(),
        now: new Date(),
        refreshTtlMs: seconds(60),
      }),
    ).resolves.toEqual({ outcome: 'unknown' });

    const created = await sessions.createSession({
      userId,
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: null,
      now: new Date(),
      sessionExpiresAt: new Date(Date.now() + seconds(60)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(Date.now() + seconds(60)),
      maxActiveSessions: 10,
    });
    const token = await prisma.refreshToken.findFirstOrThrow({
      where: { sessionId: created.sessionId },
    });

    await expect(
      sessions.rotateRefreshToken({
        tokenHash: token.tokenHash,
        nextTokenHash: hash(),
        now: new Date(Date.now() + seconds(120)),
        refreshTtlMs: seconds(60),
      }),
    ).resolves.toEqual({ outcome: 'unknown' });
  });

  it('revokes the session behind a refresh token hash', async () => {
    const now = new Date();
    const created = await sessions.createSession({
      userId,
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(3_600)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
      maxActiveSessions: 10,
    });
    const token = await prisma.refreshToken.findFirstOrThrow({
      where: { sessionId: created.sessionId },
    });

    await expect(
      sessions.revokeSessionByRefreshTokenHash(token.tokenHash, 'logout', now),
    ).resolves.toBe(userId);
    await expect(sessions.isSessionActive(created.sessionId, userId, now)).resolves.toBe(false);
    await expect(
      prisma.session.findUniqueOrThrow({ where: { id: created.sessionId } }),
    ).resolves.toMatchObject({ revokedReason: 'logout' });

    // An unknown hash is not an error: the client is simply already logged out.
    await expect(
      sessions.revokeSessionByRefreshTokenHash(hash(), 'logout', now),
    ).resolves.toBeNull();
  });

  it('revokes every session and token of a user at once', async () => {
    const now = new Date();
    const open = () => ({
      userId,
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(3_600)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
      maxActiveSessions: 10,
    });
    const first = await sessions.createSession(open());
    const second = await sessions.createSession(open());

    await sessions.revokeAllUserSessions(userId, 'refresh_reuse', now);

    await expect(sessions.isSessionActive(first.sessionId, userId, now)).resolves.toBe(false);
    await expect(sessions.isSessionActive(second.sessionId, userId, now)).resolves.toBe(false);
    await expect(
      prisma.refreshToken.count({
        where: { sessionId: { in: [first.sessionId, second.sessionId] }, revokedAt: null },
      }),
    ).resolves.toBe(0);
  });

  it('reports a duplicate phone or username as taken instead of throwing', async () => {
    const now = new Date();
    const shared = {
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(3_600)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
    };
    const existing = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

    await expect(
      sessions.createAccount({
        ...shared,
        userId: randomUUID(),
        phone: existing.phone,
        username: username(),
      }),
    ).resolves.toBeNull();

    await expect(
      sessions.createAccount({
        ...shared,
        userId: randomUUID(),
        phone: phone(),
        username: existing.username,
      }),
    ).resolves.toBeNull();

    await expect(sessions.isUsernameTaken(existing.username.toUpperCase())).resolves.toBe(true);
  });
});

describeWithDatabase('auth session cap and per-user revocation (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let sessions: PrismaSessionRepository;
  const seededUsers: string[] = [];
  const CAP = 3;

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    sessions = new PrismaSessionRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: seededUsers } } });
      await prisma.$disconnect();
    }
  });

  /** A user plus the session `createAccount` opens for them. */
  const seedUser = async (): Promise<{ userId: string; sessionId: string }> => {
    const userId = randomUUID();
    const now = new Date();
    const created = await sessions.createAccount({
      userId,
      phone: phone(),
      username: username(),
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: 'jest',
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(60 * 60 * 24 * 30)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
    });

    if (created === null) throw new Error('could not seed an account');

    seededUsers.push(userId);

    return { userId, sessionId: created.sessionId };
  };

  /** One more device: `createSession` enforces the cap inside its transaction. */
  const addSession = async (userId: string): Promise<string> => {
    const now = new Date();
    const issued = await sessions.createSession({
      userId,
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: 'jest',
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(60 * 60 * 24 * 30)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
      maxActiveSessions: CAP,
    });

    return issued.sessionId;
  };

  /** Both columns default to the wall clock, so the fixtures pin them. */
  const backdate = async (sessionId: string, minutes: number): Promise<void> => {
    const at = new Date(Date.now() - minutes * 60_000);

    await prisma.session.update({
      where: { id: sessionId },
      data: { createdAt: at, lastUsedAt: at },
    });
  };

  it('evicts the oldest session to stay within the cap', async () => {
    const owner = await seedUser();
    await backdate(owner.sessionId, 40);

    const second = await addSession(owner.userId);
    await backdate(second, 30);

    const third = await addSession(owner.userId);
    await backdate(third, 20);

    // Cap 3 + 1: the very first session is the one that must go.
    const fourth = await addSession(owner.userId);

    const rows = await prisma.session.findMany({ where: { userId: owner.userId } });

    expect(rows).toHaveLength(4);
    expect(rows.find((row) => row.id === owner.sessionId)).toMatchObject({
      revokedAt: expect.any(Date) as Date,
      revokedReason: 'session_cap',
    });
    expect(
      rows
        .filter((row) => row.revokedAt === null)
        .map((row) => row.id)
        .sort(),
    ).toEqual([second, third, fourth].sort());

    // The evicted session takes its refresh tokens with it.
    await expect(
      prisma.refreshToken.count({ where: { sessionId: owner.sessionId, revokedAt: null } }),
    ).resolves.toBe(0);
  });

  it('lists the newest sessions of one user first, hashes excluded', async () => {
    const owner = await seedUser();
    const older = await addSession(owner.userId);
    const newer = await addSession(owner.userId);
    const stranger = await seedUser();

    await backdate(owner.sessionId, 30);
    await backdate(older, 20);
    await backdate(newer, 5);

    const listed = await sessions.listActiveSessions(owner.userId, new Date());
    const foreign = await sessions.listActiveSessions(stranger.userId, new Date());

    expect(listed.map((entry) => entry.id)).toEqual([newer, older, owner.sessionId]);
    expect(Object.keys(listed[0] ?? {})).toEqual([
      'id',
      'deviceLabel',
      'createdAt',
      'lastUsedAt',
      'expiresAt',
    ]);
    // Another account's sessions never appear in the list.
    expect(foreign.map((entry) => entry.id)).toEqual([stranger.sessionId]);
  });

  it('refuses to revoke a session that belongs to somebody else', async () => {
    const stranger = await seedUser();
    const intruder = await seedUser();

    await expect(
      sessions.revokeUserSession(stranger.sessionId, intruder.userId, 'user_revoked', new Date()),
    ).resolves.toBe(false);
    await expect(
      sessions.isSessionActive(stranger.sessionId, stranger.userId, new Date()),
    ).resolves.toBe(true);

    await expect(
      sessions.revokeUserSession(stranger.sessionId, stranger.userId, 'user_revoked', new Date()),
    ).resolves.toBe(true);
    await expect(
      sessions.isSessionActive(stranger.sessionId, stranger.userId, new Date()),
    ).resolves.toBe(false);
    // Revoking twice is not an error, it is simply a no-op.
    await expect(
      sessions.revokeUserSession(stranger.sessionId, stranger.userId, 'user_revoked', new Date()),
    ).resolves.toBe(false);
  });
});
