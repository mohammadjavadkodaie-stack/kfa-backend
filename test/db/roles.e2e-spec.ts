import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import { Role } from '../../src/auth/roles';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * The role model as the runtime role sees it. `DATABASE_URL_TEST` must point at
 * `kfa_app`, so these checks fail if the migration, the enum or the column
 * grants are wrong - the guard's single query is the one under test, not a
 * hand-written equivalent.
 */

function phone(): string {
  return `+1555${randomBytes(4).readUInt32BE(0)}`;
}

function username(): string {
  return `role_${randomBytes(6).toString('hex')}`;
}

describeWithDatabase('role model (PostgreSQL)', () => {
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
      if (createdUsers.length > 0) {
        await prisma.user.deleteMany({ where: { id: { in: createdUsers } } });
      }

      await prisma.$disconnect();
    }
  });

  async function createUser(
    data: { role?: Role; identityVerifier?: boolean } = {},
  ): Promise<{ id: string; role: string; identityVerifier: boolean; status: string }> {
    const user = await prisma.user.create({
      data: { phone: phone(), username: username(), ...data },
      select: { id: true, role: true, identityVerifier: true, status: true },
    });

    createdUsers.push(user.id);

    return user;
  }

  it('stores a role enum with exactly the four assignable roles', async () => {
    const labels = await prisma.$queryRaw<{ label: string }[]>`
      SELECT unnest(enum_range(NULL::"Role"))::text AS label
    `;

    expect(labels.map((row) => row.label)).toEqual(['USER', 'ATHLETE', 'ADMIN', 'OWNER']);
  });

  it('exposes the verifier flag and the role default the schema declares', async () => {
    const columns = await prisma.$queryRaw<
      {
        column_name: string;
        data_type: string;
        is_nullable: string;
        column_default: string | null;
      }[]
    >`
      SELECT column_name, data_type, is_nullable, column_default::text AS column_default
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'users'
        AND column_name IN ('role', 'identity_verifier')
      ORDER BY column_name
    `;

    expect(columns).toEqual([
      {
        column_name: 'identity_verifier',
        data_type: 'boolean',
        is_nullable: 'NO',
        column_default: 'false',
      },
      {
        column_name: 'role',
        data_type: 'USER-DEFINED',
        is_nullable: 'NO',
        column_default: `'USER'::"Role"`,
      },
    ]);
  });

  it('defaults a new account to USER without the verifier permission', async () => {
    const user = await createUser();

    expect(user).toMatchObject({ role: 'USER', identityVerifier: false, status: 'ACTIVE' });
  });

  it('leaves no account without an explicit verifier value', async () => {
    const [counts] = await prisma.$queryRaw<{ total: bigint; unset: bigint }[]>`
      SELECT count(*) AS total,
             count(*) FILTER (WHERE "identity_verifier" IS NULL) AS unset
      FROM "users"
    `;

    // The column is NOT NULL, so this also proves existing rows took the
    // default when the migration added it.
    expect(Number(counts?.unset ?? -1)).toBe(0);
  });

  it('returns the stored role and verifier flag from the guard lookup', async () => {
    const user = await createUser({ role: Role.ADMIN, identityVerifier: true });
    const device = await prisma.device.create({
      data: { userId: user.id, deviceKeyHash: randomBytes(32).toString('hex') },
      select: { id: true },
    });
    const session = await prisma.session.create({
      data: { userId: user.id, deviceId: device.id, expiresAt: new Date(Date.now() + 60_000) },
      select: { id: true },
    });
    const now = new Date();

    await expect(sessions.findActiveSession(session.id, user.id, now)).resolves.toEqual({
      sessionId: session.id,
      userId: user.id,
      role: Role.ADMIN,
      identityVerifier: true,
      status: 'ACTIVE',
    });

    // A session id paired with another user resolves to nothing.
    await expect(sessions.findActiveSession(session.id, randomUUID(), now)).resolves.toBeNull();

    // A change made by an admin is visible on the very next lookup: neither
    // value ever comes from the token. OWNER is provisioned outside the
    // runtime role (the owner trigger refuses it), so this is a demotion.
    await prisma.user.update({
      where: { id: user.id },
      data: { role: Role.ATHLETE, identityVerifier: false },
    });

    await expect(sessions.findActiveSession(session.id, user.id, now)).resolves.toMatchObject({
      role: Role.ATHLETE,
      identityVerifier: false,
    });
  });

  it('reports a blocked account instead of hiding the session', async () => {
    const user = await createUser({ role: Role.ATHLETE });
    const device = await prisma.device.create({
      data: { userId: user.id, deviceKeyHash: randomBytes(32).toString('hex') },
      select: { id: true },
    });
    const session = await prisma.session.create({
      data: { userId: user.id, deviceId: device.id, expiresAt: new Date(Date.now() + 60_000) },
      select: { id: true },
    });

    await prisma.user.update({ where: { id: user.id }, data: { status: 'BLOCKED' } });

    // The row comes back with its status, so the guard decides; the session
    // itself is still live and is not silently deleted.
    await expect(
      sessions.findActiveSession(session.id, user.id, new Date()),
    ).resolves.toMatchObject({ status: 'BLOCKED' });
  });

  it('refuses a revoked or expired session', async () => {
    const user = await createUser();
    const device = await prisma.device.create({
      data: { userId: user.id, deviceKeyHash: randomBytes(32).toString('hex') },
      select: { id: true },
    });
    const revoked = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: device.id,
        expiresAt: new Date(Date.now() + 60_000),
        revokedAt: new Date(),
      },
      select: { id: true },
    });
    const expired = await prisma.session.create({
      data: {
        userId: user.id,
        deviceId: device.id,
        expiresAt: new Date(Date.now() - 60_000),
      },
      select: { id: true },
    });
    const now = new Date();

    await expect(sessions.findActiveSession(revoked.id, user.id, now)).resolves.toBeNull();
    await expect(sessions.findActiveSession(expired.id, user.id, now)).resolves.toBeNull();
  });
});
