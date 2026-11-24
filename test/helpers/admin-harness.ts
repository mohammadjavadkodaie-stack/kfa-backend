import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../../src/auth/in-memory-session.repository';
import { EmailProofService } from '../../src/auth/email/email-proof';
import { Role } from '../../src/auth/roles';
import { InMemoryTotpRepository } from '../../src/auth/totp/in-memory-totp.repository';
import { InMemoryBillingStore } from './in-memory-billing-store';
import type { RateLimitDecision, RateLimitService } from '../../src/rate-limit/rate-limit.service';
import type { CreateTestAppOptions } from './create-test-app';
import { createTestApp } from './create-test-app';
import {
  TEST_ACCOUNT_PASSWORD,
  signInByEmail,
  signUpByEmail,
  type EmailAccountInput,
} from './email-account';
import { InMemoryProofNonceStore } from './proof-nonce-store';
import type { TestEnvOverrides } from './test-env';

/**
 * The fixture the admin e2e suites share: the real application over an
 * in-memory session store and an in-memory audit table, so a suite reads what
 * the API wrote without a database and without Redis.
 *
 * Accounts are created through the real email sign-up endpoint, and only their
 * access level is set directly - that is the one fact a client cannot choose
 * for itself.
 */

/** The explicit limiter is out of scope here: always admit. */
class PermissiveRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  /** The read-only variant: reports the same budget without billing a hit. */
  async peek(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
}

export interface AdminAuditRow {
  readonly action: string;
  readonly actorId: string | null;
  readonly targetId: string | null;
  readonly metadata: Record<string, unknown>;
  readonly hash: string;
  readonly createdAt: Date;
}

/** Same in-memory Prisma replacement as the moderation suite: real hashing, no rows. */
function createAuditPrisma(): {
  prisma: object;
  rows: AdminAuditRow[];
  /** Active identity documents per owner, so a suite can grant the submit precondition. */
  documents: Map<string, number>;
} {
  const rows: AdminAuditRow[] = [];
  // Empty unless a suite fills it: every owner reads as "no active document".
  const documents = new Map<string, number>();

  const tx = {
    $executeRaw: (): Promise<number> => Promise.resolve(1),
    auditLog: {
      findFirst: (): Promise<{ hash: string; createdAt: Date } | null> => {
        const last = rows[rows.length - 1];

        return Promise.resolve(
          last === undefined ? null : { hash: last.hash, createdAt: last.createdAt },
        );
      },
      create: ({ data }: { data: AdminAuditRow }): Promise<AdminAuditRow> => {
        rows.push(data);

        return Promise.resolve(data);
      },
    },
    identityDocument: {
      count: ({ where }: { where: { ownerUserId: string } }): Promise<number> =>
        Promise.resolve(documents.get(where.ownerUserId) ?? 0),
    },
  };

  const prisma = {
    $connect: (): Promise<void> => Promise.resolve(),
    $disconnect: (): Promise<void> => Promise.resolve(),
    $transaction: (callback: (client: typeof tx) => Promise<unknown>): Promise<unknown> =>
      callback(tx),
    // No profile is under review unless a suite says so, so the document
    // services keep their unlocked behaviour in every other suite.
    athleteProfile: {
      findUnique: (): Promise<null> => Promise.resolve(null),
    },
    identityDocument: {
      count: ({ where }: { where: { ownerUserId: string } }): Promise<number> =>
        Promise.resolve(documents.get(where.ownerUserId) ?? 0),
    },
  };

  return { prisma, rows, documents };
}

/** An account as the suite sees it: one live token plus the row behind it. */
export interface AdminAccount extends Required<EmailAccountInput> {
  readonly token: string;
  readonly userId: string;
  readonly sessionId: string;
}

/**
 * Builds one application per suite. `prefix` keeps the generated usernames
 * readable in a failure report; every suite owns its own store, so the counters
 * never collide between suites.
 */
export async function createAdminHarness(
  prefix = 'admin',
  extra: CreateTestAppOptions = {},
  env: TestEnvOverrides = {},
) {
  const sessions = new InMemorySessionRepository();
  const auditPrisma = createAuditPrisma();
  const billing = new InMemoryBillingStore();
  let sequence = 0;

  const app: NestExpressApplication = await createTestApp(env, {
    prisma: auditPrisma.prisma,
    billingStore: billing,
    sessionRepository: sessions,
    totpRepository: new InMemoryTotpRepository(),
    proofNonceStore: new InMemoryProofNonceStore(),
    rateLimit: new PermissiveRateLimit() as unknown as RateLimitService,
    // One more in-memory store for a suite that needs it; omitted everywhere else.
    ...extra,
  });
  const proofs = app.get(EmailProofService);

  const server = () => request(app.getHttpServer());

  const post = (path: string, token?: string, body?: object) => {
    const call = server().post(path);
    const authorized = token === undefined ? call : call.set('Authorization', `Bearer ${token}`);

    return body === undefined ? authorized : authorized.send(body);
  };

  const del = (path: string, token?: string) => {
    const call = server().delete(path);

    return token === undefined ? call : call.set('Authorization', `Bearer ${token}`);
  };

  const get = (path: string, token: string) =>
    server().get(path).set('Authorization', `Bearer ${token}`);

  /** Registers through the real endpoint, then sets the role and the step-up. */
  async function signUp(role: Role, withStepUp = false): Promise<AdminAccount> {
    sequence += 1;

    const username = `${prefix}_${sequence}`;
    const email = `${prefix}_${sequence}@example.com`;
    const password = TEST_ACCOUNT_PASSWORD;

    const response = await signUpByEmail(app, { email, username, password });

    if (response.status !== 200) throw new Error(`the registration of ${username} failed`);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`the account of ${username} was not stored`);

    sessions.setUserRole(stored.id, { role });

    const session = [...sessions.sessions.values()].find((row) => row.userId === stored.id);

    if (session === undefined) throw new Error(`the session of ${username} was not stored`);

    // Staff sessions sit behind the second-factor gate; fixtures start past it.
    if (withStepUp) await sessions.markStepUp(session.id, stored.id);

    return {
      token: (response.body as { accessToken: string }).accessToken,
      userId: stored.id,
      sessionId: session.id,
      email,
      username,
      password,
    };
  }

  /** A new session for an existing account: a token the old ones do not share. */
  async function signIn(account: AdminAccount): Promise<string> {
    const response = await signInByEmail(app, account);

    if (response.status !== 200) throw new Error('the account could not sign in');

    return (response.body as { accessToken: string }).accessToken;
  }

  /** The audit rows of one action, optionally only those about one target. */
  const rows = (action: string, targetId?: string) =>
    auditPrisma.rows.filter(
      (row) => row.action === action && (targetId === undefined || row.targetId === targetId),
    );

  return {
    app,
    sessions,
    proofs,
    billing,
    post,
    del,
    get,
    signUp,
    signIn,
    rows,
    documents: auditPrisma.documents,
    close: () => app.close(),
  };
}

export type AdminHarness = Awaited<ReturnType<typeof createAdminHarness>>;
