import type { Prisma, PrismaClient } from '@prisma/client';
import { randomBytes, randomUUID } from 'node:crypto';
import { AuditService } from '../../src/audit/audit.service';
import { createTestAuditService, createTestPrisma, describeWithDatabase } from './helpers/database';

/** 64 lowercase hex characters: a format-valid audit hash / prev_hash value. */
function randomHash(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Chain-integrity checks can only fire on a real write, but audit_log is
 * append-only: a probe row may never be deleted afterwards, and the table must
 * not be assumed to be empty. Every attempt therefore runs inside an
 * interactive transaction that is always rolled back, so no probe can persist or
 * fork the chain for the neighbouring suites.
 *
 * Resolves with the error the conflicting write raised; fails loudly if a write
 * that should have been rejected was accepted.
 */
async function expectWriteRejected(
  prisma: PrismaClient,
  attempt: (tx: Prisma.TransactionClient) => Promise<void>,
): Promise<Error> {
  const rollbackMarker = 'audit-log-probe-rollback';
  let rejection: unknown = null;

  try {
    await prisma.$transaction(async (tx) => {
      try {
        await attempt(tx);
      } catch (error) {
        rejection = error;
      }

      // Abort unconditionally: this rolls back every probe row.
      throw new Error(rollbackMarker);
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : '';

    if (!message.includes(rollbackMarker)) {
      throw error;
    }
  }

  if (rejection === null) {
    throw new Error('the conflicting write was accepted');
  }

  return rejection as Error;
}

/**
 * Proves the database itself refuses to rewrite history. Run against the
 * `kfa_app` role: UPDATE/DELETE/TRUNCATE must fail (privilege + trigger), the
 * role must not be able to run DDL either, and the chain may neither fork nor
 * grow a second genesis row.
 */
describeWithDatabase('audit_log append-only guarantees (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let audit: AuditService;

  beforeAll(async () => {
    prisma = createTestPrisma();
    audit = createTestAuditService(prisma);
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('has the update, delete and truncate triggers installed', async () => {
    const triggers = await prisma.$queryRaw<Array<{ tgname: string }>>`
      SELECT tgname
      FROM pg_trigger
      WHERE tgrelid = 'public.audit_log'::regclass
        AND NOT tgisinternal
      ORDER BY tgname
    `;

    expect(triggers.map((row) => row.tgname)).toEqual([
      'audit_log_no_delete',
      'audit_log_no_truncate',
      'audit_log_no_update',
    ]);
  });

  it('runs as kfa_app with SELECT and INSERT only', async () => {
    const [role] = await prisma.$queryRaw<Array<{ current_user: string }>>`SELECT current_user`;

    expect(role?.current_user).toBe('kfa_app');

    const [privileges] = await prisma.$queryRaw<
      Array<{
        can_select: boolean;
        can_insert: boolean;
        can_update: boolean;
        can_delete: boolean;
        can_truncate: boolean;
      }>
    >`
      SELECT
        has_table_privilege(current_user, 'public.audit_log', 'SELECT') AS can_select,
        has_table_privilege(current_user, 'public.audit_log', 'INSERT') AS can_insert,
        has_table_privilege(current_user, 'public.audit_log', 'UPDATE') AS can_update,
        has_table_privilege(current_user, 'public.audit_log', 'DELETE') AS can_delete,
        has_table_privilege(current_user, 'public.audit_log', 'TRUNCATE') AS can_truncate
    `;

    expect(privileges).toEqual({
      can_select: true,
      can_insert: true,
      can_update: false,
      can_delete: false,
      can_truncate: false,
    });
  });

  it('rejects UPDATE and leaves the row untouched', async () => {
    const row = await audit.record({ action: 'db.test.update-probe' });

    await expect(
      prisma.auditLog.update({ where: { id: row.id }, data: { action: 'tampered' } }),
    ).rejects.toThrow(/append-only|permission denied/i);

    const stored = await prisma.auditLog.findUniqueOrThrow({ where: { id: row.id } });

    expect(stored.action).toBe('db.test.update-probe');
    expect(stored.hash).toBe(row.hash);
  });

  it('rejects DELETE and keeps the row', async () => {
    const row = await audit.record({ action: 'db.test.delete-probe' });

    await expect(prisma.auditLog.delete({ where: { id: row.id } })).rejects.toThrow(
      /append-only|permission denied/i,
    );

    await expect(prisma.auditLog.count({ where: { id: row.id } })).resolves.toBe(1);
  });

  it('rejects raw UPDATE and DELETE statements', async () => {
    const row = await audit.record({ action: 'db.test.raw-probe' });

    await expect(
      prisma.$executeRawUnsafe(
        `UPDATE audit_log SET action = 'tampered' WHERE id = $1::uuid`,
        row.id,
      ),
    ).rejects.toThrow(/append-only|permission denied/i);

    await expect(
      prisma.$executeRawUnsafe('DELETE FROM audit_log WHERE action = $1', 'db.test.raw-probe'),
    ).rejects.toThrow(/append-only|permission denied/i);
  });

  it('rejects TRUNCATE', async () => {
    await expect(prisma.$executeRawUnsafe('TRUNCATE TABLE audit_log')).rejects.toThrow(
      /append-only|permission denied/i,
    );
  });

  it('cannot run DDL against audit_log', async () => {
    await expect(
      prisma.$executeRawUnsafe('ALTER TABLE audit_log ADD COLUMN tamper text'),
    ).rejects.toThrow(/permission denied|must be owner/i);

    await expect(prisma.$executeRawUnsafe('DROP TABLE audit_log')).rejects.toThrow(
      /permission denied|must be owner/i,
    );
  });

  it('rejects a second row that reuses an existing prev_hash (chain cannot fork)', async () => {
    const prevHash = randomHash();

    const rejection = await expectWriteRejected(prisma, async (tx) => {
      // First row claims prevHash; the second one claims the same predecessor,
      // which would fork history.
      await tx.$executeRawUnsafe(
        'INSERT INTO audit_log (action, prev_hash, hash) VALUES ($1, $2, $3)',
        'db.test.fork.seed',
        prevHash,
        randomHash(),
      );
      await tx.$executeRawUnsafe(
        'INSERT INTO audit_log (action, prev_hash, hash) VALUES ($1, $2, $3)',
        'db.test.fork.duplicate',
        prevHash,
        randomHash(),
      );
    });

    // Prisma surfaces unique violations in its own shape, e.g.
    // Raw query failed. Code: `23505`. Message: `Key (prev_hash)=(<hash>) already exists.`
    expect(rejection.message).toMatch(/23505/);
    expect(rejection.message).toMatch(/already exists/i);
    expect(rejection.message).toMatch(/Key \(prev_hash\)=/);
  });

  it('rejects a second row with a NULL prev_hash (single genesis row)', async () => {
    const rejection = await expectWriteRejected(prisma, async (tx) => {
      await tx.$executeRawUnsafe(
        'INSERT INTO audit_log (action, hash) VALUES ($1, $2)',
        'db.test.genesis.seed',
        randomHash(),
      );
      await tx.$executeRawUnsafe(
        'INSERT INTO audit_log (action, hash) VALUES ($1, $2)',
        'db.test.genesis.duplicate',
        randomHash(),
      );
    });

    // Same Prisma shape for the partial unique index on NULL prev_hash:
    // Raw query failed. Code: `23505`. Message: `Key ((true))=(t) already exists.`
    expect(rejection.message).toMatch(/23505/);
    expect(rejection.message).toMatch(/already exists/i);
    expect(rejection.message).toMatch(/Key \(\(true\)\)=/);
  });

  it('cannot INSERT, UPDATE or DELETE the migration history table', async () => {
    await expect(
      prisma.$executeRawUnsafe(
        `INSERT INTO "_prisma_migrations" (id, checksum, migration_name, started_at, applied_steps_count)
         VALUES ($1, $2, $3, now(), 0)`,
        randomUUID(),
        randomHash(),
        'db_test_migration_probe',
      ),
    ).rejects.toThrow(/permission denied/i);

    await expect(
      prisma.$executeRawUnsafe('UPDATE "_prisma_migrations" SET applied_steps_count = 0'),
    ).rejects.toThrow(/permission denied/i);

    await expect(prisma.$executeRawUnsafe('DELETE FROM "_prisma_migrations"')).rejects.toThrow(
      /permission denied/i,
    );
  });
});
