import { randomBytes } from 'node:crypto';
import { Prisma, PrismaClient } from '@prisma/client';
import {
  createBreakGlassPrisma,
  createTestPrisma,
  describeWithBreakGlass,
} from './helpers/database';

/**
 * Stage 3.4b: the database guarantees at most one OWNER row.
 *
 * The trigger from 20261103120000_owner_protection_trigger fences off the
 * runtime role only; the partial unique index `users_single_owner_key` applies
 * to every role. The assertions below therefore use the break-glass connection
 * (`kfa_migrator`) to reach the index, and the runtime connection (`kfa_app`)
 * to confirm the trigger still refuses first with 42501, not 23505.
 */

type Role = 'ADMIN' | 'OWNER' | 'USER';

type UserRow = { id: string; username: string; role: Role };

// The table checks want E.164 and a lowercase handle, so keep both valid.
const phone = (): string => `+1555${1_000_000 + (randomBytes(4).readUInt32BE(0) % 9_000_000)}`;
const runTag = randomBytes(4).toString('hex');
const username = (prefix: string): string => `${prefix}${runTag}${randomBytes(3).toString('hex')}`;

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

describeWithBreakGlass('single owner index (PostgreSQL)', () => {
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
         RETURNING id::text AS id, username, role::text AS role`,
        phone(),
        username(role === 'OWNER' ? 'one' : 'mem'),
        role,
      ),
    );

    if (row === undefined) {
      throw new Error('seeding a user returned no row');
    }

    seeded.push(row.id);

    return row;
  }

  async function readRole(id: string): Promise<Role | undefined> {
    const [row] = await asOperator((tx) =>
      tx.$queryRawUnsafe<{ role: Role }[]>(
        `SELECT role::text AS role FROM users WHERE id = $1::uuid`,
        id,
      ),
    );

    return row?.role;
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

  async function expectUniqueViolation(work: () => Promise<unknown>): Promise<string> {
    const error = await work().then(
      () => null,
      (caught: unknown) => caught,
    );

    expect(error).not.toBeNull();

    const text = errorText(error);

    // The index, not the trigger: a real unique violation (23505) on the
    // partial index key. Prisma's minimal error format keeps the key detail
    // but not the index name.
    expect(text).toMatch(/23505/i);
    expect(text).toMatch(/already exists|duplicate key/i);
    expect(text).not.toMatch(/42501|insufficient_privilege/i);

    return text;
  }

  async function expectRefusedByTrigger(work: () => Promise<unknown>): Promise<string> {
    const error = await work().then(
      () => null,
      (caught: unknown) => caught,
    );

    expect(error).not.toBeNull();

    const text = errorText(error);

    // The runtime path still hits the trigger's insufficient_privilege (42501).
    expect(text).toMatch(/42501|insufficient_privilege/i);
    expect(text).not.toMatch(/23505/i);

    return text;
  }

  async function countOwners(): Promise<number> {
    return countRows(`SELECT count(*)::int AS rows FROM users WHERE role = 'OWNER'`);
  }

  it('refuses a second owner written through the break-glass path', async () => {
    const attemptedPhone = phone();

    const text = await expectUniqueViolation(() =>
      asOperator((tx) =>
        tx.$executeRawUnsafe(
          `INSERT INTO users (phone, username, role) VALUES ($1, $2, 'OWNER')`,
          attemptedPhone,
          username('dup'),
        ),
      ),
    );

    // The index reports its own key, never the protected row itself.
    for (const value of [owner.id, owner.username]) {
      expect(text).not.toContain(value);
    }

    await expect(readRole(owner.id)).resolves.toBe('OWNER');
    await expect(countOwners()).resolves.toBe(1);
    await expect(
      countRows(`SELECT count(*)::int AS rows FROM users WHERE phone = $1`, attemptedPhone),
    ).resolves.toBe(0);
  });

  it('refuses a break-glass promotion while the owner still holds the role', async () => {
    await expectUniqueViolation(() =>
      asOperator((tx) =>
        tx.$executeRawUnsafe(`UPDATE users SET role = 'OWNER' WHERE id = $1::uuid`, member.id),
      ),
    );

    await expect(readRole(owner.id)).resolves.toBe('OWNER');
    await expect(readRole(member.id)).resolves.toBe('USER');
    await expect(countOwners()).resolves.toBe(1);
  });

  it('transfers ownership inside one transaction', async () => {
    // The ownership-transfer path: demote first, then promote, one transaction.
    await asOperator(async (tx) => {
      await tx.$executeRawUnsafe(`UPDATE users SET role = 'ADMIN' WHERE id = $1::uuid`, owner.id);
      await tx.$executeRawUnsafe(`UPDATE users SET role = 'OWNER' WHERE id = $1::uuid`, member.id);
    });

    await expect(readRole(owner.id)).resolves.toBe('ADMIN');
    await expect(readRole(member.id)).resolves.toBe('OWNER');
    await expect(countOwners()).resolves.toBe(1);
  });

  it('rolls a failed transfer back and leaves exactly one owner', async () => {
    // Promotion first fails, so the demotion after it never commits either.
    await expectUniqueViolation(() =>
      asOperator(async (tx) => {
        await tx.$executeRawUnsafe(
          `UPDATE users SET role = 'OWNER' WHERE id = $1::uuid`,
          member.id,
        );
        await tx.$executeRawUnsafe(`UPDATE users SET role = 'ADMIN' WHERE id = $1::uuid`, owner.id);
      }),
    );

    await expect(readRole(owner.id)).resolves.toBe('OWNER');
    await expect(readRole(member.id)).resolves.toBe('USER');
    await expect(countOwners()).resolves.toBe(1);
  });

  it('still refuses a second owner through the runtime role', async () => {
    await expectRefusedByTrigger(() =>
      appRun(
        `INSERT INTO users (phone, username, role) VALUES ($1, $2, 'OWNER')`,
        phone(),
        username('app'),
      ),
    );
    await expectRefusedByTrigger(() =>
      appRun(`UPDATE users SET role = 'OWNER' WHERE id = $1::uuid`, member.id),
    );

    await expect(readRole(owner.id)).resolves.toBe('OWNER');
    await expect(readRole(member.id)).resolves.toBe('USER');
    await expect(countOwners()).resolves.toBe(1);
  });
});
