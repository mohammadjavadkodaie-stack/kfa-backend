import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * The phone swap against a real PostgreSQL: the unique index, not a read, is
 * what decides a taken number, and the session revocations share the same
 * transaction as the write.
 *
 *   DATABASE_URL_TEST=postgresql://kfa_app:...@127.0.0.1:5432/kfa_test pnpm test:e2e
 */

const SECONDS_PER_DAY = 86_400;

const hash = () => randomBytes(32).toString('hex');
const seconds = (value: number) => value * 1_000;

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '7')
    .slice(0, 7)}`;
}

function username(): string {
  return `chg_${randomUUID().replaceAll('-', '')}`.slice(0, 30);
}

interface SeededAccount {
  readonly userId: string;
  /** The asking session first, then the others. */
  readonly sessionIds: string[];
  readonly phone: string;
}

describeWithDatabase('phone change (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let sessions: PrismaSessionRepository;
  const createdUsers: string[] = [];

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    sessions = new PrismaSessionRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: createdUsers } } });
      await prisma.$disconnect();
    }
  });

  /** One account with `others` extra sessions, each with a refresh token. */
  async function seedAccount(others: number): Promise<SeededAccount> {
    const userId = randomUUID();
    const now = new Date();
    const ownerPhone = phone();

    const account = await sessions.createAccount({
      userId,
      phone: ownerPhone,
      username: username(),
      deviceKeyHash: hash(),
      deviceBound: true,
      deviceLabel: 'jest-owner',
      now,
      sessionExpiresAt: new Date(now.getTime() + seconds(SECONDS_PER_DAY * 30)),
      refreshTokenHash: hash(),
      refreshExpiresAt: new Date(now.getTime() + seconds(SECONDS_PER_DAY * 14)),
    });

    if (account === null) throw new Error('could not seed an account');

    createdUsers.push(userId);

    const sessionIds = [account.sessionId];

    for (let index = 0; index < others; index += 1) {
      const extra = await sessions.createSession({
        userId,
        deviceKeyHash: hash(),
        deviceBound: true,
        deviceLabel: `jest-${index}`,
        now,
        sessionExpiresAt: new Date(now.getTime() + seconds(SECONDS_PER_DAY * 30)),
        refreshTokenHash: hash(),
        refreshExpiresAt: new Date(now.getTime() + seconds(SECONDS_PER_DAY * 14)),
        maxActiveSessions: 10,
      });

      sessionIds.push(extra.sessionId);
    }

    return { userId, sessionIds, phone: ownerPhone };
  }

  it('moves the number and revokes every other session with its refresh token', async () => {
    const account = await seedAccount(2);
    const owner = account.sessionIds[0] ?? '';
    const [first, second] = [account.sessionIds[1] ?? '', account.sessionIds[2] ?? ''];
    const target = phone();

    const result = await sessions.changePhone({
      userId: account.userId,
      phone: target,
      keepSessionId: owner,
      now: new Date(),
    });

    expect(result).toEqual({ outcome: 'changed', revokedSessions: 2 });

    const user = await prisma.user.findUniqueOrThrow({ where: { id: account.userId } });

    expect(user.phone).toBe(target);
    expect(user.phoneVerifiedAt).toBeInstanceOf(Date);

    const rows = await prisma.session.findMany({
      where: { id: { in: account.sessionIds } },
    });
    const byId = new Map(rows.map((row) => [row.id, row]));

    expect(byId.get(owner)).toMatchObject({ revokedAt: null, revokedReason: null });
    for (const sessionId of [first, second]) {
      expect(byId.get(sessionId)).toMatchObject({
        revokedAt: expect.any(Date) as Date,
        revokedReason: 'phone_changed',
      });
    }

    const tokens = await prisma.refreshToken.findMany({
      where: { sessionId: { in: [first, second] } },
    });

    expect(tokens).toHaveLength(2);
    for (const token of tokens) expect(token.revokedAt).toBeInstanceOf(Date);

    const ownerToken = await prisma.refreshToken.findFirstOrThrow({
      where: { sessionId: owner },
    });

    expect(ownerToken.revokedAt).toBeNull();
    await expect(sessions.findPhoneByUserId(account.userId)).resolves.toBe(target);
  });

  it('refuses a number another account already owns and leaves the caller intact', async () => {
    const owner = await seedAccount(1);
    const claimant = await seedAccount(1);
    const now = new Date();

    const result = await sessions.changePhone({
      userId: claimant.userId,
      phone: owner.phone,
      keepSessionId: claimant.sessionIds[0] ?? null,
      now,
    });

    expect(result).toEqual({ outcome: 'conflict' });

    // Nothing was written: not the number, not the revocations.
    const user = await prisma.user.findUniqueOrThrow({ where: { id: claimant.userId } });

    expect(user.phone).toBe(claimant.phone);

    const rows = await prisma.session.findMany({ where: { userId: claimant.userId } });

    for (const row of rows) expect(row.revokedAt).toBeNull();
  });

  it('reports an unknown account as not_found', async () => {
    await expect(
      sessions.changePhone({
        userId: randomUUID(),
        phone: phone(),
        keepSessionId: null,
        now: new Date(),
      }),
    ).resolves.toEqual({ outcome: 'not_found' });
  });

  it('lets exactly one of two parallel claims on the same number win', async () => {
    const first = await seedAccount(0);
    const second = await seedAccount(0);
    const target = phone();

    const claim = (account: SeededAccount) =>
      sessions.changePhone({
        userId: account.userId,
        phone: target,
        keepSessionId: account.sessionIds[0] ?? null,
        now: new Date(),
      });

    const results = await Promise.all([claim(first), claim(second)]);

    expect(results.map((result) => result.outcome).sort()).toEqual(['changed', 'conflict']);

    const holders = await prisma.user.count({ where: { phone: target } });

    expect(holders).toBe(1);
  });
});
