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
      deviceLabel: null,
      now: new Date(),
      sessionExpiresAt: new Date(Date.now() + seconds(60)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(Date.now() + seconds(60)),
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
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(3_600)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
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
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(3_600)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(3_600)),
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
