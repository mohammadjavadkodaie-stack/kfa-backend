import { randomBytes } from 'node:crypto';
import { Prisma, PrismaClient } from '@prisma/client';
import {
  createBreakGlassPrisma,
  createTestPrisma,
  describeWithBreakGlass,
} from './helpers/database';

/**
 * The owner account is provisioned outside the application. Every attempt here
 * runs as `kfa_app` (`DATABASE_URL_TEST`); seeding and re-reading the protected
 * row uses the break-glass connection (`DATABASE_URL_TEST_BREAK_GLASS`), which
 * is the path the trigger leaves open for operators.
 */

type UserRow = { id: string; phone: string; username: string; role: string; status: string };

// The table checks want E.164 and a lowercase handle, so keep both valid.
const phone = (): string => `+1555${1_000_000 + (randomBytes(4).readUInt32BE(0) % 9_000_000)}`;
const username = (prefix: string): string => `${prefix}_${randomBytes(6).toString('hex')}`;

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

describeWithBreakGlass('owner protection (PostgreSQL)', () => {
  let runtime: PrismaClient;
  let privileged: PrismaClient;
  let owner: UserRow;
  let member: UserRow;
  const seeded: string[] = [];

  const appQuery = <T>(sql: string, ...params: unknown[]) =>
    runtime.$queryRawUnsafe<T>(sql, ...params);

  const appRun = (sql: string, ...params: unknown[]) => runtime.$executeRawUnsafe(sql, ...params);

  // Break-glass, the way the trigger defines it: the write runs as a role other
  // than kfa_app. SET LOCAL lasts for the transaction, so the pooled connection
  // is back to its login role at commit.
  const asOperator = async <T>(work: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> =>
    privileged.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET LOCAL ROLE NONE');

      return work(tx);
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

  async function readOwner(): Promise<UserRow | undefined> {
    const [row] = await asOperator((tx) =>
      tx.$queryRawUnsafe<UserRow[]>(
        `SELECT id::text AS id, phone, username, role::text AS role, status::text AS status
         FROM users
         WHERE id = $1::uuid`,
        owner.id,
      ),
    );

    return row;
  }

  async function countRows(sql: string, ...params: unknown[]): Promise<number> {
    const [row] = await asOperator((tx) => tx.$queryRawUnsafe<{ rows: number }[]>(sql, ...params));

    return Number(row?.rows ?? -1);
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

  beforeAll(async () => {
    runtime = createTestPrisma();
    privileged = createBreakGlassPrisma();
    await runtime.$connect();
    await privileged.$connect();
  });

  beforeEach(async () => {
    // Every assertion below only means something as the runtime role.
    await expect(
      appQuery<{ role: string }[]>('SELECT current_user::text AS role'),
    ).resolves.toEqual([{ role: 'kfa_app' }]);

    owner = await seedUser('OWNER');
    member = await seedUser('USER');
  });

  afterEach(async () => {
    await removeSeeded();
  });

  afterAll(async () => {
    if (privileged) {
      // A failing test can leave a row behind, so this runs either way.
      await removeSeeded();
      await privileged.$disconnect();
    }

    if (runtime) {
      await runtime.$disconnect();
    }
  });

  async function expectRefused(work: () => Promise<unknown>): Promise<void> {
    const error = await work().then(
      () => null,
      (caught: unknown) => caught,
    );

    expect(error).not.toBeNull();

    const text = errorText(error);

    // Not just any failure: the trigger's insufficient_privilege (42501).
    expect(text).toMatch(/42501|insufficient_privilege/i);

    // The refusal must not echo the row it protected either.
    for (const value of [owner.id, owner.phone, owner.username]) {
      expect(text).not.toContain(value);
    }
  }

  async function expectUntouched(): Promise<void> {
    await expect(readOwner()).resolves.toEqual(owner);
    await expect(
      countRows(`SELECT count(*)::int AS rows FROM users WHERE role = 'OWNER'`),
    ).resolves.toBe(1);
  }

  it('refuses to demote the owner', async () => {
    await expectRefused(() =>
      appRun(`UPDATE users SET role = 'USER' WHERE id = $1::uuid`, owner.id),
    );
    await expectUntouched();
  });

  it('refuses to block the owner', async () => {
    await expectRefused(() =>
      appRun(`UPDATE users SET status = 'BLOCKED' WHERE id = $1::uuid`, owner.id),
    );
    await expectUntouched();
  });

  it('refuses to change the owner id', async () => {
    await expectRefused(() =>
      appRun(`UPDATE users SET id = gen_random_uuid() WHERE id = $1::uuid`, owner.id),
    );
    await expectUntouched();
  });

  it('refuses to delete the owner', async () => {
    await expectRefused(() => appRun(`DELETE FROM users WHERE id = $1::uuid`, owner.id));
    await expectUntouched();
  });

  it('refuses a second owner', async () => {
    const attemptedPhone = phone();

    await expectRefused(() =>
      appRun(
        `INSERT INTO users (phone, username, role) VALUES ($1, $2, 'OWNER')`,
        attemptedPhone,
        username('dup'),
      ),
    );

    // The refused insert left nothing behind, not even a plain account.
    await expectUntouched();
    await expect(
      countRows(`SELECT count(*)::int AS rows FROM users WHERE phone = $1`, attemptedPhone),
    ).resolves.toBe(0);
  });

  it('refuses to promote a normal account', async () => {
    await expectRefused(() =>
      appRun(`UPDATE users SET role = 'OWNER' WHERE id = $1::uuid`, member.id),
    );
    await expectUntouched();
    await expect(
      appQuery<{ role: string }[]>(
        `SELECT role::text AS role FROM users WHERE id = $1::uuid`,
        member.id,
      ),
    ).resolves.toEqual([{ role: 'USER' }]);
  });

  it('refuses to truncate the table', async () => {
    // kfa_app has no TRUNCATE privilege, so this may be refused before the
    // trigger runs; either way it is a 42501 and no row may disappear.
    await expectRefused(() => appRun('TRUNCATE TABLE users'));
    await expectUntouched();
    await expect(
      countRows(`SELECT count(*)::int AS rows FROM users WHERE id = $1::uuid`, member.id),
    ).resolves.toBe(1);
  });

  it('still lets the runtime role edit a phone and a normal account', async () => {
    const changedPhone = phone();

    await appRun(`UPDATE users SET phone = $1 WHERE id = $2::uuid`, changedPhone, owner.id);
    await appRun(`UPDATE users SET status = 'BLOCKED' WHERE id = $1::uuid`, member.id);

    await expect(
      appQuery<{ status: string }[]>(
        `SELECT status::text AS status FROM users WHERE id = $1::uuid`,
        member.id,
      ),
    ).resolves.toEqual([{ status: 'BLOCKED' }]);

    await appRun(`DELETE FROM users WHERE id = $1::uuid`, member.id);

    // The phone stays editable; role and status do not.
    await expect(readOwner()).resolves.toMatchObject({
      phone: changedPhone,
      role: 'OWNER',
      status: 'ACTIVE',
    });
    await expect(runtime.user.findUnique({ where: { id: member.id } })).resolves.toBeNull();
  });

  it('lets the break-glass path change and create an owner', async () => {
    const [inserted] = await asOperator(async (tx) => {
      await tx.$executeRawUnsafe(
        `UPDATE users SET role = 'ADMIN', status = 'BLOCKED' WHERE id = $1::uuid`,
        owner.id,
      );

      return tx.$queryRawUnsafe<UserRow[]>(
        `INSERT INTO users (phone, username, role)
         VALUES ($1, $2, 'OWNER')
         RETURNING id::text AS id, phone, username, role::text AS role, status::text AS status`,
        phone(),
        username('own'),
      );
    });

    if (inserted === undefined) {
      throw new Error('the break-glass insert returned no row');
    }

    seeded.push(inserted.id);

    await expect(readOwner()).resolves.toMatchObject({ role: 'ADMIN', status: 'BLOCKED' });
    await expect(
      appQuery<{ role: string }[]>(
        `SELECT role::text AS role FROM users WHERE id = $1::uuid`,
        inserted.id,
      ),
    ).resolves.toEqual([{ role: 'OWNER' }]);
    await expect(
      countRows(`SELECT count(*)::int AS rows FROM users WHERE role = 'OWNER'`),
    ).resolves.toBe(1);
  });

  it('keeps the same connection usable after a refusal', async () => {
    await expectRefused(() => appRun(`DELETE FROM users WHERE id = $1::uuid`, owner.id));

    await expect(
      appQuery<{ role: string }[]>('SELECT current_user::text AS role'),
    ).resolves.toEqual([{ role: 'kfa_app' }]);
    await expect(runtime.user.count({ where: { id: owner.id } })).resolves.toBe(1);
  });
});
