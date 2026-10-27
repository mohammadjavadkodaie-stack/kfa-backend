import { PrismaClient } from '@prisma/client';
import { AuditService } from '../../../src/audit/audit.service';
import type { Env } from '../../../src/config/env';
import type { PrismaService } from '../../../src/database/prisma.service';

/**
 * Database-backed suites are opt-in: they run only when DATABASE_URL_TEST is
 * set (point it at the `kfa_app` runtime role, never the migrator). Without it
 * every `describeWithDatabase` block is reported as skipped.
 */
export const TEST_DATABASE_URL = process.env.DATABASE_URL_TEST;

export const TEST_AUDIT_HMAC_KEY = 'db-test-audit-hmac-key-0123456789';

export const describeWithDatabase = TEST_DATABASE_URL ? describe : describe.skip;

export function createTestPrisma(): PrismaClient {
  if (!TEST_DATABASE_URL) {
    throw new Error('DATABASE_URL_TEST is required to run database suites');
  }

  return new PrismaClient({
    datasourceUrl: TEST_DATABASE_URL,
    log: [],
    errorFormat: 'minimal',
  });
}

export function createTestAuditService(prisma: PrismaClient): AuditService {
  return new AuditService(
    prisma as unknown as PrismaService,
    {
      AUDIT_HMAC_KEY: TEST_AUDIT_HMAC_KEY,
    } as Env,
  );
}
