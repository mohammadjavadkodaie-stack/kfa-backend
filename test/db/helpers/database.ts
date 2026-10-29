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

/**
 * The owner row may only be written by a role other than `kfa_app`, so a suite
 * that has to seed or repair one needs a second, privileged connection: point
 * `DATABASE_URL_TEST_BREAK_GLASS` at `kfa_migrator` (or the local superuser)
 * and keep `DATABASE_URL_TEST` on `kfa_app` for the assertions.
 */
export const TEST_BREAK_GLASS_URL = process.env.DATABASE_URL_TEST_BREAK_GLASS;

export const describeWithBreakGlass =
  TEST_DATABASE_URL && TEST_BREAK_GLASS_URL ? describe : describe.skip;

export function createBreakGlassPrisma(): PrismaClient {
  if (!TEST_BREAK_GLASS_URL) {
    throw new Error('DATABASE_URL_TEST_BREAK_GLASS is required for break-glass writes');
  }

  return new PrismaClient({
    datasourceUrl: TEST_BREAK_GLASS_URL,
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
