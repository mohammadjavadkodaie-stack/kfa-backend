import type { AuditLog, PrismaClient } from '@prisma/client';
import { computeAuditHash, isAuditHash } from '../../src/audit/audit-canonical';
import type { AuditService } from '../../src/audit/audit.service';
import { createTestAuditService, createTestPrisma, describeWithDatabase } from './helpers/database';

function readChain(prisma: PrismaClient): Promise<AuditLog[]> {
  return prisma.auditLog.findMany({
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

/**
 * Recomputes every hash with the same code the writer uses and checks the links.
 * Reading metadata back from `jsonb` (with its own key order) is part of the
 * test: the canonical form must survive the round trip.
 */
function verifyChain(rows: AuditLog[]): void {
  let previous: string | null = null;

  for (const row of rows) {
    expect(isAuditHash(row.hash)).toBe(true);
    expect(row.prevHash).toBe(previous);
    expect(row.hash).toBe(computeAuditHash(previous, row));
    previous = row.hash;
  }
}

describeWithDatabase('audit_log hash chain (PostgreSQL)', () => {
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

  it('links sequential appends to the current head', async () => {
    const before = await readChain(prisma);
    const head = before.at(-1)?.hash ?? null;

    const first = await audit.record({
      action: 'db.test.chain.first',
      actorRole: 'ADMIN',
      metadata: { step: 1, password: 'never-stored' },
    });
    const second = await audit.record({
      action: 'db.test.chain.second',
      targetType: 'user',
      targetId: 'target-1',
    });

    expect(first.prevHash).toBe(head);
    expect(second.prevHash).toBe(first.hash);

    const rows = await readChain(prisma);

    expect(rows.length).toBe(before.length + 2);
    verifyChain(rows);
    expect(rows.at(-1)?.hash).toBe(second.hash);
    expect(rows[rows.length - 2]?.hash).toBe(first.hash);
  });

  it('never stores redacted audit secrets', async () => {
    const row = await audit.record({
      action: 'db.test.redaction',
      metadata: { email: 'user@example.com', password: 'p@ssw0rd', nested: { otp: '123456' } },
    });

    expect(row.metadata).toEqual({
      email: 'user@example.com',
      password: '[REDACTED]',
      nested: { otp: '[REDACTED]' },
    });
  });

  it('serialises concurrent appends into a single unbroken chain', async () => {
    const before = await prisma.auditLog.count();

    await Promise.all(
      Array.from({ length: 4 }, (_unused, index) =>
        audit.record({ action: `db.test.concurrent.${index}` }),
      ),
    );

    const rows = await readChain(prisma);

    expect(rows.length).toBe(before + 4);
    verifyChain(rows);

    const timestamps = rows.map((row) => row.createdAt.getTime());

    expect(new Set(timestamps).size).toBe(timestamps.length);
    expect(timestamps).toEqual([...timestamps].sort((a, b) => a - b));
  });

  it('produces different hashes for identical actions', async () => {
    const first = await audit.record({ action: 'db.test.duplicate' });
    const second = await audit.record({ action: 'db.test.duplicate' });

    expect(first.hash).not.toBe(second.hash);
    expect(second.prevHash).toBe(first.hash);
  });
});
