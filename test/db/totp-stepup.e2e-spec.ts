import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * `sessions.stepup_at` against a real PostgreSQL, as `kfa_app`: the runtime role
 * must be able to read and write the new column, and the two statements behind
 * the step-up guard must only ever touch the caller's own live session.
 */

const unique = (prefix: string) => `${prefix}_${randomUUID().replaceAll('-', '')}`.slice(0, 30);

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '4')
    .slice(0, 7)}`;
}

const HOUR_MS = 3_600_000;

describeWithDatabase('session step-up persistence (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let repository: PrismaSessionRepository;
  const userIds: string[] = [];

  interface SeededSession {
    readonly userId: string;
    readonly sessionId: string;
  }

  /** ADMIN, not OWNER: the row trigger only fences the single owner account. */
  const seedSession = async (
    options: { readonly revoked?: boolean; readonly expired?: boolean } = {},
  ): Promise<SeededSession> => {
    const user = await prisma.user.create({
      data: { phone: phone(), username: unique('stepup'), role: 'ADMIN' },
    });

    userIds.push(user.id);

    const device = await prisma.device.create({
      data: { userId: user.id, deviceKeyHash: randomBytes(32).toString('hex') },
    });

    const now = Date.now();

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: device.id,
        deviceBound: false,
        expiresAt: new Date(options.expired === true ? now - HOUR_MS : now + HOUR_MS),
        ...(options.revoked === true ? { revokedAt: new Date(), revokedReason: 'logout' } : {}),
      },
    });

    return { userId: user.id, sessionId: session.id };
  };

  const stepUpAt = async (sessionId: string): Promise<Date | null> => {
    const row = await prisma.session.findUnique({
      where: { id: sessionId },
      select: { stepupAt: true },
    });

    return row === null ? null : row.stepupAt;
  };

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    repository = new PrismaSessionRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
      await prisma.$disconnect();
    }
  });

  it('starts with no stamp on a fresh session', async () => {
    const { userId, sessionId } = await seedSession();

    await expect(repository.getStepUpAt(sessionId, userId)).resolves.toBeNull();
  });

  it('writes the stamp with the database clock and reads the same row back', async () => {
    const { userId, sessionId } = await seedSession();
    const before = Date.now();

    await expect(repository.markStepUp(sessionId, userId)).resolves.toBe(true);

    const stamp = await repository.getStepUpAt(sessionId, userId);

    expect(stamp).toBeInstanceOf(Date);
    // The app host clock is never used, so allow only drift, not a stale value.
    expect(Math.abs((stamp as Date).getTime() - before)).toBeLessThan(60_000);
    expect(await stepUpAt(sessionId)).toEqual(stamp);

    // A second step-up moves the stamp forward without creating anything.
    await new Promise((resolve) => setTimeout(resolve, 10));
    await expect(repository.markStepUp(sessionId, userId)).resolves.toBe(true);

    const renewed = await repository.getStepUpAt(sessionId, userId);

    expect((renewed as Date).getTime()).toBeGreaterThanOrEqual((stamp as Date).getTime());
    await expect(prisma.session.count({ where: { userId } })).resolves.toBe(1);
  });

  it('refuses a session that belongs to another user', async () => {
    const mine = await seedSession();
    const other = await seedSession();

    await expect(repository.markStepUp(other.sessionId, mine.userId)).resolves.toBe(false);
    await expect(repository.getStepUpAt(other.sessionId, mine.userId)).resolves.toBeNull();
    await expect(stepUpAt(other.sessionId)).resolves.toBeNull();
  });

  it('refuses a revoked session', async () => {
    const { userId, sessionId } = await seedSession({ revoked: true });

    await expect(repository.markStepUp(sessionId, userId)).resolves.toBe(false);
    await expect(repository.getStepUpAt(sessionId, userId)).resolves.toBeNull();
    await expect(stepUpAt(sessionId)).resolves.toBeNull();
  });

  it('refuses an expired session', async () => {
    const { userId, sessionId } = await seedSession({ expired: true });

    await expect(repository.markStepUp(sessionId, userId)).resolves.toBe(false);
    await expect(repository.getStepUpAt(sessionId, userId)).resolves.toBeNull();
  });

  it('refuses an unknown session id', async () => {
    const { userId } = await seedSession();

    await expect(repository.markStepUp(randomUUID(), userId)).resolves.toBe(false);
    await expect(repository.getStepUpAt(randomUUID(), userId)).resolves.toBeNull();
  });

  it('lets the runtime role read and write the column directly', async () => {
    const { sessionId } = await seedSession();

    const updated = await prisma.$executeRaw`
      UPDATE "sessions" SET "stepup_at" = now() WHERE "id" = ${sessionId}::uuid
    `;

    expect(updated).toBe(1);

    const rows = await prisma.$queryRaw<{ stepup_at: Date }[]>`
      SELECT "stepup_at" FROM "sessions" WHERE "id" = ${sessionId}::uuid
    `;

    expect(rows[0]?.stepup_at).toBeInstanceOf(Date);
  });
});
