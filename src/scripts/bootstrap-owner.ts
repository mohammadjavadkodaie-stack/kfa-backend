import 'reflect-metadata';

/**
 * First-owner bootstrap CLI.
 *
 * Break-glass tool that promotes one existing account to the single OWNER role
 * after a fresh deployment, when the API has no owner yet to promote anyone.
 * It is the only supported path around the owner-protection trigger, and it is
 * built to be safe to re-run:
 *
 * - Requires `--confirm`; anything else prints usage and exits 2.
 * - Refuses with a non-zero exit when any OWNER already exists; nothing is
 *   modified.
 * - The account must already exist (created through the email sign-up flow);
 *   unknown or unusable addresses are refused generically, exactly like a
 *   login attempt, and no audit row is written.
 * - The role change goes through the application's compare-and-set repository
 *   path (no raw SQL), so a concurrent promotion cannot be doubled.
 * - One audit row is appended only after the role change won: action
 *   `owner.bootstrapped`, actor `system:bootstrap-cli`, masked email.
 *
 * Run inside the backend container (see docs/DEPLOY.md):
 *
 * ```sh
 * docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml \
 *   exec backend node dist/scripts/bootstrap-owner.js --email ops@example.com --confirm
 * ```
 */
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AuditService } from '../audit/audit.service';
import { maskEmail, normalizeEmail } from '../auth/email/email';
import { PrismaSessionRepository } from '../auth/prisma-session.repository';
import { Role } from '../auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../auth/session.repository';
import { ENV } from '../config/config.module';
import { loadEnv, type Env } from '../config/env';
import { PrismaService } from '../database/prisma.service';

/** Actor recorded in the audit trail for every change this CLI makes. */
export const BOOTSTRAP_ACTOR = 'system:bootstrap-cli';

const USAGE = 'usage: node dist/scripts/bootstrap-owner.js --email <address> --confirm';
const REFUSAL_UNKNOWN_ACCOUNT = 'refused: no eligible account for that address\n';

export type BootstrapArgs = { readonly email: string } | { readonly error: string };

/** Minimal argv parsing: `--email` (with a value) and `--confirm` are mandatory. */
export function parseBootstrapArgs(argv: readonly string[]): BootstrapArgs {
  let email: string | undefined;
  let confirmed = false;
  let index = 0;

  while (index < argv.length) {
    const arg = argv[index];

    if (arg === undefined) break;

    if (arg === '--confirm') {
      confirmed = true;
      index += 1;
      continue;
    }

    if (arg === '--email') {
      const value = argv[index + 1];

      if (value === undefined) return { error: '--email requires a value' };

      email = value;
      index += 2;
      continue;
    }

    // Deliberately vague: operator input is never echoed back.
    return { error: 'unexpected argument' };
  }

  if (email === undefined) return { error: '--email is required' };
  if (!confirmed) return { error: '--confirm is required' };

  return { email };
}

/**
 * The environment this CLI runs with: the validated process environment with
 * the Prisma client pointed at the break-glass (migrator) credentials. The
 * owner-protection trigger lets every role except the runtime role create the
 * first OWNER, so the bootstrap must not connect as `kfa_app`.
 */
export function scriptEnv(): Env {
  const base = loadEnv();

  return Object.freeze({ ...base, DATABASE_URL: base.MIGRATION_DATABASE_URL ?? base.DATABASE_URL });
}

export interface BootstrapOwnerDeps {
  readonly sessions: SessionRepository;
  readonly audit: AuditService;
}

export type BootstrapOutcome = 'promoted' | 'unknown_account' | 'owner_exists' | 'conflict';

/**
 * Promotes an existing account to the single OWNER role.
 *
 * The order carries the guarantees: the account must exist, no OWNER may exist
 * (checked before anything is written), the role change is one compare-and-set
 * through the session repository, and the audit row is appended only after the
 * role change won. The address is only ever written to the audit trail masked.
 */
export async function bootstrapOwner(
  deps: BootstrapOwnerDeps,
  email: string,
): Promise<BootstrapOutcome> {
  const normalized = normalizeEmail(email);

  if (normalized === null) return 'unknown_account';

  const account = await deps.sessions.findUserByEmail(normalized);

  if (account === null) return 'unknown_account';

  if ((await deps.sessions.countUsersByRole(Role.OWNER)) > 0) return 'owner_exists';

  if (!(await deps.sessions.setRoleIf(account.id, account.role, Role.OWNER))) {
    return 'conflict';
  }

  await deps.audit.record({
    action: 'owner.bootstrapped',
    actorRole: BOOTSTRAP_ACTOR,
    targetType: 'user',
    targetId: account.id,
    metadata: { account: maskEmail(normalized), from: account.role, to: Role.OWNER },
  });

  return 'promoted';
}

/**
 * The wiring the CLI needs and nothing else: no HTTP server, no captcha, and
 * no provider that dials anything at boot. `PrismaService` is built from the
 * script environment (break-glass credentials), while the session repository
 * and audit service are wired exactly like the API modules.
 */
@Module({
  providers: [
    { provide: ENV, useFactory: scriptEnv },
    { provide: PrismaService, useFactory: (env: Env) => new PrismaService(env), inject: [ENV] },
    { provide: SESSION_REPOSITORY, useClass: PrismaSessionRepository },
    {
      provide: AuditService,
      useFactory: (prisma: PrismaService, env: Env) => new AuditService(prisma, env),
      inject: [PrismaService, ENV],
    },
  ],
})
export class BootstrapOwnerModule {}

async function main(): Promise<void> {
  const parsed = parseBootstrapArgs(process.argv.slice(2));

  if ('error' in parsed) {
    process.stderr.write(`${USAGE}\nerror: ${parsed.error}\n`);
    process.exitCode = 2;
    return;
  }

  const normalized = normalizeEmail(parsed.email);

  if (normalized === null) {
    process.stderr.write(REFUSAL_UNKNOWN_ACCOUNT);
    process.exitCode = 1;
    return;
  }

  const app = await NestFactory.createApplicationContext(BootstrapOwnerModule, {
    // The CLI prints its own lines; Nest boot logs would only add noise.
    logger: false,
  });

  try {
    const outcome = await bootstrapOwner(
      {
        sessions: app.get<SessionRepository>(SESSION_REPOSITORY),
        audit: app.get(AuditService),
      },
      normalized,
    );

    switch (outcome) {
      case 'promoted':
        process.stdout.write(`owner bootstrapped for ${maskEmail(normalized)}\n`);
        break;
      case 'unknown_account':
        process.stderr.write(REFUSAL_UNKNOWN_ACCOUNT);
        process.exitCode = 1;
        break;
      case 'owner_exists':
        process.stderr.write('refused: an OWNER account already exists\n');
        process.exitCode = 1;
        break;
      case 'conflict':
        process.stderr.write('refused: the account changed concurrently; nothing was modified\n');
        process.exitCode = 1;
        break;
    }
  } finally {
    await app.close();
  }
}

if (require.main === module) {
  void main().catch((error: unknown) => {
    // Same rule as `main.ts`: print the message, never env values or stacks.
    const message = error instanceof Error ? error.message : 'Unknown failure';
    process.stderr.write(`bootstrap-owner failed: ${message}\n`);
    process.exitCode = 1;
  });
}
