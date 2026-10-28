import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

const hash = () => randomBytes(32).toString('hex');
const unique = (prefix: string) => `${prefix}_${randomUUID().replaceAll('-', '')}`.slice(0, 30);
const expectRejected = async (work: () => Promise<unknown>) => expect(work()).rejects.toThrow();

describeWithDatabase('auth foundation constraints (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let userId: string;
  let deviceId: string;
  let sessionId: string;
  let userPhone: string;
  let username: string;

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    userPhone = `+1415${randomUUID()
      .replaceAll('-', '')
      .replace(/[^0-9]/g, '1')
      .slice(0, 7)}`;
    username = unique('dbtest');
    const user = await prisma.user.create({ data: { phone: userPhone, username } });
    userId = user.id;
    const device = await prisma.device.create({ data: { userId, deviceKeyHash: hash() } });
    deviceId = device.id;
    const session = await prisma.session.create({
      data: { userId, deviceId, expiresAt: new Date(Date.now() + 3600000) },
    });
    sessionId = session.id;
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: userId } });
      await prisma.$disconnect();
    }
  });

  it('enforces unique phone, username and refresh token hash', async () => {
    await expectRejected(() =>
      prisma.user.create({ data: { phone: userPhone, username: unique('other') } }),
    );
    await expectRejected(() =>
      prisma.user.create({
        data: {
          phone: `+1415${randomUUID()
            .replaceAll('-', '')
            .replace(/[^0-9]/g, '2')
            .slice(0, 7)}`,
          username,
        },
      }),
    );
    await prisma.refreshToken.create({
      data: { sessionId, tokenHash: hash(), expiresAt: new Date(Date.now() + 3600000) },
    });
    const token = await prisma.refreshToken.findFirstOrThrow({ where: { sessionId } });
    await expectRejected(() =>
      prisma.refreshToken.create({
        data: { sessionId, tokenHash: token.tokenHash, expiresAt: new Date(Date.now() + 3600000) },
      }),
    );
  });

  it('rejects format and length checks', async () => {
    await expectRejected(() =>
      prisma.user.create({ data: { phone: '123', username: unique('bad') } }),
    );
    await expectRejected(() =>
      prisma.user.create({ data: { phone: '+14155552671', username: 'Bad Name' } }),
    );
    await expectRejected(() => prisma.device.create({ data: { userId, deviceKeyHash: 'bad' } }));
    await expectRejected(() =>
      prisma.session.update({ where: { id: sessionId }, data: { revokedReason: 'x'.repeat(101) } }),
    );
  });

  it('cascades user deletion through sessions and refresh tokens', async () => {
    const token = await prisma.refreshToken.create({
      data: { sessionId, tokenHash: hash(), expiresAt: new Date(Date.now() + 3600000) },
    });
    await prisma.user.delete({ where: { id: userId } });
    await expect(prisma.session.findUnique({ where: { id: sessionId } })).resolves.toBeNull();
    await expect(prisma.refreshToken.findUnique({ where: { id: token.id } })).resolves.toBeNull();
    await expect(prisma.device.findUnique({ where: { id: deviceId } })).resolves.toBeNull();
  });
});
