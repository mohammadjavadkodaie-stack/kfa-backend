import type { PrismaClient } from '@prisma/client';
import { AuditService } from '../../src/audit/audit.service';
import { createTestAuditService, createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * Proves the database itself refuses to rewrite history. Run against the
 * `kfa_app` role: UPDATE/DELETE/TRUNCATE must fail (privilege + trigger), and
 * the role must not be able to run DDL either.
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
      prisma.$executeRawUnsafe(`UPDATE audit_log SET action = 'tampered' WHERE id = $1`, row.id),
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
});
