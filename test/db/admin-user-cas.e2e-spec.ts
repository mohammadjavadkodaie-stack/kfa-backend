import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import { Role } from '../../src/auth/roles';
import type { PrismaService } from '../../src/database/prisma.service';
import {
  createBreakGlassPrisma,
  createTestPrisma,
  describeWithBreakGlass,
} from './helpers/database';

/**
 * The compare-and-set helpers run as `kfa_app` (`DATABASE_URL_TEST`). Seeding
 * and removing the protected owner row uses the break-glass connection
 * (`DATABASE_URL_TEST_BREAK_GLASS`), exactly like the owner-protection suite.
 */

type UserRow = { id: string; phone: string; username: string; role: string; status: string };

const phone = (): string => `+1555${1_000_000 + (randomBytes(4).readUInt32BE(0) % 9_000_000)}`;
const username = (prefix: string): string => `${prefix}_${randomBytes(6).toString('hex')}`;

type CasResult = { readonly ok: boolean } | { readonly error: unknown };

async function settle(call: Promise<boolean>): Promise<CasResult> {
  return call.then(
    (ok) => ({ ok }),
    (error: unknown) => ({ error }),
  );
}

function errorText(error: unknown): string {
  const known = error as {
    code?: string;
    message?: string;
    meta?: { code?: string; message?: string };
  };

  return [known.code, known.message, known.meta?.code, known.meta?.message, String(error)]
    .filter((part) => typeof part === 'string')
    .join(' | ');
}

describeWithBreakGlass('admin user CAS (PostgreSQL)', () => {
  let runtime: PrismaClient;
  let privileged: PrismaClient;
  let repository: PrismaSessionRepository;
  let owner: UserRow;
  let member: UserRow;
  const seeded: string[] = [];

  const asOperator = async <T>(work: (client: PrismaClient) => Promise<T>): Promise<T> =>
    privileged.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET LOCAL ROLE NONE');

      return work(tx as unknown as PrismaClient);
    });

  async function seedUser(role: 'OWNER' | 'USER'): Promise<UserRow> {
    const [row] = await asOperator((tx) =>
      tx.$queryRawUnsafe<UserRow[]>(
        `INSERT INTO users (phone, username, role)
         VALUES ($1, $2, $3::"Role")
         RETURNING id::text AS id, phone, username, role::text AS role, status::text AS status`,
        phone(),
        username(role === 'OWNER' ? 'own' : 'usr'),
        role,
      ),
    );

    if (row === undefined) {
      throw new Error('seeding a user returned no row');
    }

    seeded.push(row.id);

    return row;
  }

  async function removeSeeded(): Promise<void> {
    const ids = seeded.splice(0, seeded.length);

    if (ids.length === 0) {
      return;
    }

    await asOperator(async (tx) => {
      for (const id of ids) {
        await tx.$executeRawUnsafe(`DELETE FROM users WHERE id = $1::uuid`, id);
      }
    });
  }

  function readUser(id: string) {
    return runtime.user.findUnique({ where: { id }, select: { role: true, status: true } });
  }

  beforeAll(async () => {
    runtime = createTestPrisma();
    privileged = createBreakGlassPrisma();
    repository = new PrismaSessionRepository(runtime as unknown as PrismaService);
    await runtime.$connect();
    await privileged.$connect();
  });

  beforeEach(async () => {
    await expect(
      runtime.$queryRawUnsafe<{ role: string }[]>('SELECT current_user::text AS role'),
    ).resolves.toEqual([{ role: 'kfa_app' }]);

    owner = await seedUser('OWNER');
    member = await seedUser('USER');
  });

  afterEach(async () => {
    await removeSeeded();
  });

  afterAll(async () => {
    if (privileged) {
      await removeSeeded();
      await privileged.$disconnect();
    }

    if (runtime) {
      await runtime.$disconnect();
    }
  });

  it('lets one of two parallel status changes win', async () => {
    const results = await Promise.all([
      repository.setStatusIf(member.id, 'ACTIVE', 'BLOCKED'),
      repository.setStatusIf(member.id, 'ACTIVE', 'BLOCKED'),
    ]);

    expect(results.filter((changed) => changed)).toHaveLength(1);
    await expect(readUser(member.id)).resolves.toMatchObject({ status: 'BLOCKED' });
  });

  it('lets one of two parallel role changes win', async () => {
    const results = await Promise.all([
      repository.setRoleIf(member.id, Role.USER, Role.ADMIN),
      repository.setRoleIf(member.id, Role.USER, Role.ADMIN),
    ]);

    expect(results.filter((changed) => changed)).toHaveLength(1);
    await expect(readUser(member.id)).resolves.toMatchObject({ role: 'ADMIN' });
  });

  it('returns false when the expected value is stale', async () => {
    await expect(repository.setStatusIf(member.id, 'BLOCKED', 'ACTIVE')).resolves.toBe(false);
    await expect(repository.setRoleIf(member.id, Role.ADMIN, Role.USER)).resolves.toBe(false);

    await expect(readUser(member.id)).resolves.toMatchObject({ role: 'USER', status: 'ACTIVE' });
  });

  it('cannot change the owner status as the runtime role', async () => {
    const result = await settle(repository.setStatusIf(owner.id, 'ACTIVE', 'BLOCKED'));

    if ('error' in result) {
      // The trigger refuses the statement; either shape is accepted, but the
      // row itself must be untouched.
      expect(errorText(result.error)).toMatch(/42501|insufficient_privilege/i);
      expect(errorText(result.error)).not.toContain(owner.id);
    } else {
      expect(result.ok).toBe(false);
    }

    await expect(readUser(owner.id)).resolves.toMatchObject({ role: 'OWNER', status: 'ACTIVE' });
  });

  it('cannot change the owner role as the runtime role', async () => {
    const result = await settle(repository.setRoleIf(owner.id, Role.OWNER, Role.USER));

    if ('error' in result) {
      expect(errorText(result.error)).toMatch(/42501|insufficient_privilege/i);
    } else {
      expect(result.ok).toBe(false);
    }

    await expect(readUser(owner.id)).resolves.toMatchObject({ role: 'OWNER', status: 'ACTIVE' });
  });
});
