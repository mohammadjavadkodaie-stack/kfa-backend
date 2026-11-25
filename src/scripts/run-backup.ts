import 'reflect-metadata';

/**
 * Nightly encrypted backup CLI.
 *
 * Runs `pg_dump --format=custom`, encrypts the result with AES-256-GCM under
 * BACKUP_ENCRYPTION_KEY, verifies that the encrypted file can be decrypted back
 * into a real `pg_dump` archive, and mails the encrypted file to both owner
 * mailboxes. The point of the verification step is that a backup nobody has ever
 * opened is not a backup: the GCM tag and the archive magic are checked on the
 * host, before anything is delivered.
 *
 * - Files are written to the OS temp directory and removed only after at least
 *   one delivery succeeded. A failure of any step keeps what is on disk, so the
 *   run can be inspected, and reports itself by email and through the exit code.
 * - Everything is logged as one structured line per event; names, sizes and exit
 *   codes only - never a secret, a connection string or database content.
 * - The CLI boots the smallest possible Nest context (environment + email
 *   transport). It never opens a database connection of its own and never
 *   touches Redis.
 *
 * Run it from cron (see docs/DEPLOY.md), or by hand:
 *
 * ```sh
 * docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml \
 *   exec backend node dist/scripts/run-backup.js
 * ```
 */
import { execFile } from 'node:child_process';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import pino from 'pino';
import { maskEmail } from '../auth/email/email';
import {
  createEmailProvider,
  EMAIL_PROVIDER,
  type EmailProvider,
} from '../auth/email/email.provider';
import { ENV } from '../config/config.module';
import { BACKUP_ENCRYPTION_KEY_BYTES, loadEnv, type Env } from '../config/env';

/** Every `pg_dump --format=custom` archive starts with these five bytes. */
export const PGDUMP_MAGIC = Buffer.from('PGDMP', 'utf8');

/** AES-256-GCM: 96-bit IV and a 128-bit authentication tag, then the ciphertext. */
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

/** The dump command is never built from a shell string and never takes the URL. */
const DUMP_COMMAND = 'pg_dump';
const DUMP_ARGS = ['--format=custom', '--no-owner', '--no-privileges', '--no-password'];

/** A hung dump must not leave a cron job running forever. */
const DUMP_TIMEOUT_MS = 60 * 60 * 1000;

/** The notice an owner receives when a run could not deliver a dump. */
export const BACKUP_FAILURE_NOTICE = 'backup_failed' as const;

export type BackupOutcome =
  | 'delivered'
  | 'config_missing'
  | 'dump_failed'
  | 'seal_failed'
  | 'integrity_failed'
  | 'undelivered'
  | 'failed';

/** The three logging methods this CLI uses; a pino logger satisfies it. */
export type BackupLogger = {
  info: (data: object, message: string) => void;
  warn: (data: object, message: string) => void;
  error: (data: object, message: string) => void;
};

/** The settings a backup run needs; all three are required in production. */
export type BackupEnv = Pick<
  Env,
  'DATABASE_URL' | 'BACKUP_ENCRYPTION_KEY' | 'BACKUP_NOTIFY_EMAIL' | 'BACKUP_NOTIFY_EMAIL_EMERGENCY'
>;

export interface BackupDeps {
  readonly env: BackupEnv;
  readonly email: EmailProvider;
  /** Defaults to a silent logger: the CLI passes pino, a suite passes a mock. */
  readonly logger?: BackupLogger;
  readonly now?: () => Date;
  readonly tempDir?: string;
  /**
   * Sealing and opening are injectable for exactly one reason: a suite has to be
   * able to hand the pipeline a file that was tampered with after it was sealed.
   */
  readonly seal?: (plain: Buffer, key: Buffer) => Buffer;
  readonly open?: (sealed: Buffer, key: Buffer) => Buffer;
}

const NOOP_LOGGER: BackupLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/** Seals `plain` as `iv || authTag || ciphertext` under a random IV. */
export function sealDump(plain: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);

  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

/**
 * Opens a sealed dump and verifies it. The GCM tag is authenticated here, so a
 * truncated, tampered or wrongly-keyed file throws instead of returning rubbish.
 */
export function openDump(sealed: Buffer, key: Buffer): Buffer {
  if (sealed.length < IV_BYTES + AUTH_TAG_BYTES) {
    throw new Error('sealed backup is too short to hold an iv and an auth tag');
  }

  const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, IV_BYTES));
  decipher.setAuthTag(sealed.subarray(IV_BYTES, IV_BYTES + AUTH_TAG_BYTES));

  return Buffer.concat([
    decipher.update(sealed.subarray(IV_BYTES + AUTH_TAG_BYTES)),
    decipher.final(),
  ]);
}

/** True when the decrypted bytes really are a custom-format `pg_dump` archive. */
export function isPgDumpArchive(plain: Buffer): boolean {
  return plain.subarray(0, PGDUMP_MAGIC.length).equals(PGDUMP_MAGIC);
}

/** Decodes BACKUP_ENCRYPTION_KEY or returns null; the key is never logged. */
export function backupKeyOf(value: string | undefined): Buffer | null {
  if (value === undefined) return null;

  const key = Buffer.from(value, 'base64url');

  return key.length === BACKUP_ENCRYPTION_KEY_BYTES ? key : null;
}

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * libpq settings for one connection string. The URL is passed as environment
 * variables instead of an argument because arguments are readable by every
 * process on the host, while a child process environment is not.
 */
export function pgConnectionEnv(databaseUrl: string): Record<string, string> {
  const url = new URL(databaseUrl);
  const settings: Record<string, string> = {};
  const database = url.pathname.replace(/^\//u, '');

  if (url.hostname.length > 0) settings.PGHOST = url.hostname;
  if (url.port.length > 0) settings.PGPORT = url.port;
  if (url.username.length > 0) settings.PGUSER = decodeComponent(url.username);
  if (url.password.length > 0) settings.PGPASSWORD = decodeComponent(url.password);
  if (database.length > 0) settings.PGDATABASE = database;

  const sslmode = url.searchParams.get('sslmode');
  if (sslmode !== null) settings.PGSSLMODE = sslmode;

  return settings;
}

/**
 * Runs `pg_dump` into `filePath` without a shell, so no part of the connection
 * string can be interpreted as a command. `--no-password` keeps a missing
 * credential from turning into an interactive prompt inside cron.
 */
export function runPgDump(filePath: string, databaseUrl: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      DUMP_COMMAND,
      [...DUMP_ARGS, '-f', filePath],
      {
        env: { ...process.env, ...pgConnectionEnv(databaseUrl) },
        timeout: DUMP_TIMEOUT_MS,
        windowsHide: true,
      },
      (error) => {
        if (error === null) resolve();
        else reject(error);
      },
    );
  });
}

/** One ISO timestamp, compacted into a filename-safe stamp (`20261125T000000`). */
function stampOf(date: Date): string {
  return date.toISOString().slice(0, 19).replace(/[-:]/gu, '');
}

/** Removes a working file; a leftover is reported but never hides the outcome. */
async function removeQuietly(filePath: string, logger: BackupLogger, at: string): Promise<void> {
  try {
    await rm(filePath, { force: true });
  } catch {
    logger.warn(
      { event: 'backup.cleanup_failed', at, file: basename(filePath) },
      'a working file could not be removed',
    );
  }
}

/**
 * Tells both owners that the run failed. A plain notice and never an attachment:
 * the point of the alert is that it arrives when there is no dump to send.
 */
async function alertOwners(
  email: EmailProvider,
  owners: readonly string[],
  logger: BackupLogger,
  at: string,
): Promise<void> {
  try {
    const results = await Promise.allSettled(
      owners.map((to) => email.sendNotice({ to, kind: BACKUP_FAILURE_NOTICE })),
    );
    const failed = results.filter((result) => result.status === 'rejected').length;

    if (failed > 0) {
      logger.warn(
        { event: 'backup.alert_failed', at, failed },
        'a backup failure alert was not delivered',
      );
    }
  } catch {
    logger.warn({ event: 'backup.alert_failed', at }, 'the backup failure alert could not be sent');
  }
}

/** A failed child is reported by exit code only: no stderr, no command line. */
function childExitCode(error: unknown): number | string | null {
  const code = (error as { code?: unknown } | null)?.code;

  return typeof code === 'number' || typeof code === 'string' ? code : null;
}

async function backupOnce(deps: BackupDeps): Promise<BackupOutcome> {
  const logger = deps.logger ?? NOOP_LOGGER;
  const startedAt = (deps.now ?? (() => new Date()))();
  const at = startedAt.toISOString();
  const seal = deps.seal ?? sealDump;
  const open = deps.open ?? openDump;
  const key = backupKeyOf(deps.env.BACKUP_ENCRYPTION_KEY);
  const primary = deps.env.BACKUP_NOTIFY_EMAIL;
  const emergency = deps.env.BACKUP_NOTIFY_EMAIL_EMERGENCY;

  // Fail closed: a dump that cannot be encrypted or delivered must not be
  // produced at all, so nothing is written and nothing is mailed.
  if (key === null || primary === undefined || emergency === undefined) {
    const missing = [
      ...(key === null ? ['BACKUP_ENCRYPTION_KEY'] : []),
      ...(primary === undefined ? ['BACKUP_NOTIFY_EMAIL'] : []),
      ...(emergency === undefined ? ['BACKUP_NOTIFY_EMAIL_EMERGENCY'] : []),
    ];

    logger.error(
      { event: 'backup.failed', phase: 'config', at, missing },
      'nightly backup is not configured',
    );
    process.exitCode = 1;
    return 'config_missing';
  }

  const owners: readonly string[] = [primary, emergency];
  const directory = deps.tempDir ?? tmpdir();
  const dumpPath = join(
    directory,
    `kfa-backup-${stampOf(startedAt)}-${randomBytes(4).toString('hex')}.dump`,
  );
  const sealedPath = `${dumpPath}.enc`;

  try {
    await runPgDump(dumpPath, deps.env.DATABASE_URL);
  } catch (error) {
    // A half-written dump is unencrypted and not restorable, so it is removed
    // before the owners are told - and it is never mailed.
    await removeQuietly(dumpPath, logger, at);
    await alertOwners(deps.email, owners, logger, at);
    logger.error(
      { event: 'backup.failed', phase: 'dump', at, exitCode: childExitCode(error) },
      'pg_dump did not finish',
    );
    process.exitCode = 1;
    return 'dump_failed';
  }

  let sealed: Buffer;

  try {
    sealed = seal(await readFile(dumpPath), key);
    await writeFile(sealedPath, sealed, { mode: 0o600 });
  } catch {
    await alertOwners(deps.email, owners, logger, at);
    logger.error({ event: 'backup.failed', phase: 'seal', at }, 'the dump could not be encrypted');
    process.exitCode = 1;
    return 'seal_failed';
  }

  // Verification opens what is actually on disk: a tampered or truncated file
  // fails the GCM tag here, and a file that decrypts to anything other than a
  // custom-format archive fails the magic check - both before anything is sent.
  try {
    if (!isPgDumpArchive(open(await readFile(sealedPath), key))) {
      throw new Error('the decrypted dump is not a pg_dump archive');
    }
  } catch {
    await alertOwners(deps.email, owners, logger, at);
    logger.error(
      { event: 'backup.failed', phase: 'integrity', at, bytes: sealed.length },
      'the encrypted backup failed verification',
    );
    process.exitCode = 1;
    return 'integrity_failed';
  }

  const filename = basename(sealedPath);
  const deliveries = await Promise.allSettled(
    owners.map((to) => deps.email.sendBackup({ to, filename, content: sealed })),
  );

  for (const [index, result] of deliveries.entries()) {
    if (result.status === 'rejected') {
      logger.warn(
        { event: 'backup.delivery_failed', at, owner: maskEmail(owners[index] ?? '') },
        'a backup email was not delivered',
      );
    }
  }

  const delivered = deliveries.filter((result) => result.status === 'fulfilled').length;

  if (delivered === 0) {
    // Both copies are intact, so they stay on disk: only the delivery failed.
    // No alert is sent in this case: the transport just refused both messages,
    // so a third one would fail for the same reason.
    logger.error(
      { event: 'backup.failed', phase: 'delivery', at, bytes: sealed.length },
      'the nightly backup was not delivered',
    );
    process.exitCode = 1;
    return 'undelivered';
  }

  await removeQuietly(dumpPath, logger, at);
  await removeQuietly(sealedPath, logger, at);
  logger.info(
    {
      event: 'backup.delivered',
      at,
      bytes: sealed.length,
      delivered,
      failed: deliveries.length - delivered,
    },
    'nightly backup delivered',
  );

  return 'delivered';
}

/**
 * One backup run. Never throws: every failure becomes one structured line, a
 * kept-or-removed pair of working files, and an exit code that this function
 * sets itself so a caller cannot forget it.
 */
export async function runBackup(deps: BackupDeps): Promise<BackupOutcome> {
  try {
    return await backupOnce(deps);
  } catch {
    (deps.logger ?? NOOP_LOGGER).error(
      { event: 'backup.failed', phase: 'unexpected' },
      'nightly backup failed',
    );
    process.exitCode = 1;
    return 'failed';
  }
}

/**
 * The wiring the CLI needs and nothing else: the validated environment and the
 * selected email transport. No HTTP server, no database provider and no Redis
 * client, so a run cannot accidentally dial anything but SMTP/HTTPS.
 */
@Module({
  providers: [
    { provide: ENV, useFactory: () => loadEnv() },
    {
      provide: EMAIL_PROVIDER,
      useFactory: (env: Env): EmailProvider => createEmailProvider(env),
      inject: [ENV],
    },
  ],
})
export class BackupModule {}

async function main(): Promise<void> {
  // Booting both validates the environment and builds the transport; an invalid
  // environment fails here and is reported by the guard below, names only.
  const app = await NestFactory.createApplicationContext(BackupModule, { logger: false });

  try {
    const env = app.get<Env>(ENV);

    await runBackup({
      env,
      email: app.get<EmailProvider>(EMAIL_PROVIDER),
      logger: pino({ level: env.LOG_LEVEL }),
    });
  } finally {
    await app.close();
  }
}

if (require.main === module) {
  void main().catch((error: unknown) => {
    // Same rule as `main.ts`: print the message, never env values or stacks.
    const message = error instanceof Error ? error.message : 'Unknown failure';
    process.stderr.write(`run-backup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
