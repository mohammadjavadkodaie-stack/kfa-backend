import { execFile } from 'node:child_process';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeEmailProvider } from '../auth/email/email.provider';
import type {
  BackupEmailMessage,
  EmailCodeMessage,
  EmailNoticeMessage,
  EmailProvider,
  ReviewResultMessage,
} from '../auth/email/email.provider';
import {
  isPgDumpArchive,
  openDump,
  pgConnectionEnv,
  runBackup,
  sealDump,
  type BackupEnv,
  type BackupLogger,
} from './run-backup';

// The child process is always mocked: a suite never runs pg_dump against a real
// database, and the mock is what writes (or refuses to write) the dump file.
jest.mock('node:child_process', () => ({ execFile: jest.fn() }));

const KEY = Buffer.from('kfa-test-only-backup-enc-key-001', 'utf8');
const KEY_ENCODED = KEY.toString('base64url');
const OWNER = 'owner@example.com';
const EMERGENCY = 'owner-emergency@example.com';
const DATABASE_URL = 'postgresql://kfa_app:app-secret@db.internal:5432/kfa?sslmode=require';

/** What a real custom-format dump starts with, plus a body a spec can compare. */
const DUMP = Buffer.concat([
  Buffer.from('PGDMP', 'utf8'),
  Buffer.from([1, 14, 0]),
  Buffer.from('kfa-test-only-dump-body', 'utf8'),
]);

const execFileMock = execFile as unknown as jest.Mock;

interface DumpCall {
  readonly file: string;
  readonly args: readonly string[];
  readonly options: { readonly env?: Record<string, string> };
}

let lastCall: DumpCall | null = null;
let tempDir = '';

function dumpCall(): DumpCall {
  if (lastCall === null) throw new Error('pg_dump was never invoked');

  return lastCall;
}

/** Makes the mocked pg_dump write `content` into the `-f` target it was given. */
function pgDumpWrites(content: Buffer): void {
  execFileMock.mockImplementation(
    (
      file: string,
      args: readonly string[],
      options: DumpCall['options'],
      callback: (error: Error | null) => void,
    ) => {
      lastCall = { file, args, options };
      const flag = args.indexOf('-f');
      const target = args[flag + 1] ?? '';

      void writeFile(target, content).then(() => callback(null));
    },
  );
}

/** Makes the mocked pg_dump fail the way a refused connection does. */
function pgDumpFails(code: number | string = 1): void {
  execFileMock.mockImplementation(
    (
      file: string,
      args: readonly string[],
      options: DumpCall['options'],
      callback: (error: Error | null) => void,
    ) => {
      lastCall = { file, args, options };
      callback(Object.assign(new Error('Command failed: pg_dump'), { code }));
    },
  );
}

/** Seals correctly and then corrupts one byte, the way a bad disk would. */
function tamperedSeal(plain: Buffer, key: Buffer): Buffer {
  const sealed = sealDump(plain, key);
  const last = sealed.length - 1;

  sealed[last] = (sealed[last] ?? 0) ^ 0xff;

  return sealed;
}

/** A recording transport whose deliveries can be made to fail per address. */
class BackupEmailStub implements EmailProvider {
  readonly backups: BackupEmailMessage[] = [];
  readonly notices: EmailNoticeMessage[] = [];
  readonly failing: string[] = [];

  async sendCode(_input: EmailCodeMessage): Promise<void> {}

  async sendNotice(input: EmailNoticeMessage): Promise<void> {
    this.notices.push(input);
  }

  async sendReviewResult(_input: ReviewResultMessage): Promise<void> {}

  async sendBackup(input: BackupEmailMessage): Promise<void> {
    if (this.failing.includes(input.to)) throw new Error('delivery refused');

    this.backups.push(input);
  }
}

function logger(): BackupLogger & { info: jest.Mock; warn: jest.Mock; error: jest.Mock } {
  return { info: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

function env(overrides: Partial<BackupEnv> = {}): BackupEnv {
  return {
    DATABASE_URL,
    BACKUP_ENCRYPTION_KEY: KEY_ENCODED,
    BACKUP_NOTIFY_EMAIL: OWNER,
    BACKUP_NOTIFY_EMAIL_EMERGENCY: EMERGENCY,
    ...overrides,
  };
}

/** Names left in the working directory, so a spec can see what was kept. */
async function leftovers(): Promise<readonly string[]> {
  return readdir(tempDir);
}

beforeEach(async () => {
  execFileMock.mockReset();
  lastCall = null;
  process.exitCode = 0;
  tempDir = await mkdtemp(join(tmpdir(), 'kfa-backup-spec-'));
});

afterEach(async () => {
  process.exitCode = 0;
  await rm(tempDir, { recursive: true, force: true });
});

describe('runBackup', () => {
  it('encrypts the dump, verifies it, mails both owners and removes both files', async () => {
    pgDumpWrites(DUMP);
    const email = new FakeEmailProvider();
    const log = logger();

    await expect(
      runBackup({
        env: env(),
        email,
        logger: log,
        tempDir,
        now: () => new Date('2026-11-25T00:00:00.000Z'),
      }),
    ).resolves.toBe('delivered');

    expect(process.exitCode).toBe(0);
    expect(email.backups).toHaveLength(2);
    expect(email.backups.map((backup) => backup.to)).toEqual([OWNER, EMERGENCY]);

    const attachment = email.backups[0];

    if (attachment === undefined) throw new Error('no backup was attached');

    expect(attachment.filename).toMatch(/^kfa-backup-20261125T000000-[0-9a-f]{8}\.dump\.enc$/u);
    // The attachment is the ciphertext, and it opens back into the real dump.
    expect(attachment.content.equals(DUMP)).toBe(false);
    expect(openDump(attachment.content, KEY).equals(DUMP)).toBe(true);

    expect(await leftovers()).toEqual([]);
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'backup.delivered',
        bytes: attachment.content.length,
        delivered: 2,
        failed: 0,
      }),
      expect.any(String),
    );
    expect(log.error).not.toHaveBeenCalled();
  });

  it('passes the connection as libpq environment, never as a command argument', async () => {
    pgDumpWrites(DUMP);

    await runBackup({ env: env(), email: new FakeEmailProvider(), tempDir });

    expect(dumpCall().file).toBe('pg_dump');
    expect(dumpCall().args).toEqual([
      '--format=custom',
      '--no-owner',
      '--no-privileges',
      '--no-password',
      '-f',
      expect.stringContaining('kfa-backup-'),
    ]);
    expect(dumpCall().args.join(' ')).not.toContain('app-secret');
    expect(dumpCall().options.env).toMatchObject({
      PGHOST: 'db.internal',
      PGPORT: '5432',
      PGUSER: 'kfa_app',
      PGPASSWORD: 'app-secret',
      PGDATABASE: 'kfa',
      PGSSLMODE: 'require',
    });
  });

  it('keeps both files and alerts without an attachment when the file was tampered with', async () => {
    pgDumpWrites(DUMP);
    const email = new BackupEmailStub();
    const log = logger();

    await expect(
      runBackup({ env: env(), email, logger: log, tempDir, seal: tamperedSeal }),
    ).resolves.toBe('integrity_failed');

    expect(process.exitCode).toBe(1);
    expect(email.backups).toHaveLength(0);
    expect(email.notices.map((notice) => notice.to)).toEqual([OWNER, EMERGENCY]);
    expect(email.notices.every((notice) => notice.kind === 'backup_failed')).toBe(true);
    expect((await leftovers()).filter((name) => name.endsWith('.dump'))).toHaveLength(1);
    expect((await leftovers()).filter((name) => name.endsWith('.enc'))).toHaveLength(1);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'backup.failed', phase: 'integrity' }),
      expect.any(String),
    );
  });

  it('refuses a dump that decrypts to something other than a pg_dump archive', async () => {
    pgDumpWrites(Buffer.from('this is not a pg_dump archive'));
    const email = new BackupEmailStub();

    await expect(runBackup({ env: env(), email, tempDir })).resolves.toBe('integrity_failed');

    expect(process.exitCode).toBe(1);
    expect(email.backups).toHaveLength(0);
    expect(email.notices).toHaveLength(2);
    expect(await leftovers()).toHaveLength(2);
  });

  it('still succeeds and cleans up when only one of the two deliveries fails', async () => {
    pgDumpWrites(DUMP);
    const email = new BackupEmailStub();
    const log = logger();

    email.failing.push(OWNER);

    await expect(runBackup({ env: env(), email, logger: log, tempDir })).resolves.toBe('delivered');

    expect(process.exitCode).toBe(0);
    expect(email.backups.map((backup) => backup.to)).toEqual([EMERGENCY]);
    expect(await leftovers()).toEqual([]);
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'backup.delivery_failed', owner: 'o***@example.com' }),
      expect.any(String),
    );
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'backup.delivered', delivered: 1, failed: 1 }),
      expect.any(String),
    );
  });

  it('keeps both files and fails when neither delivery arrives', async () => {
    pgDumpWrites(DUMP);
    const email = new BackupEmailStub();
    const log = logger();

    email.failing.push(OWNER, EMERGENCY);

    await expect(runBackup({ env: env(), email, logger: log, tempDir })).resolves.toBe(
      'undelivered',
    );

    expect(process.exitCode).toBe(1);
    expect(await leftovers()).toHaveLength(2);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'backup.failed', phase: 'delivery' }),
      expect.any(String),
    );
  });

  it('catches a failing pg_dump, sends no attachment and removes the partial file', async () => {
    pgDumpFails(1);
    const email = new BackupEmailStub();
    const log = logger();

    await expect(runBackup({ env: env(), email, logger: log, tempDir })).resolves.toBe(
      'dump_failed',
    );

    expect(process.exitCode).toBe(1);
    expect(email.backups).toHaveLength(0);
    expect(email.notices).toHaveLength(2);
    expect(await leftovers()).toEqual([]);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'backup.failed', phase: 'dump', exitCode: 1 }),
      expect.any(String),
    );
  });

  it('refuses to run without the key or an owner address, and writes nothing', async () => {
    const email = new BackupEmailStub();
    const log = logger();

    await expect(
      runBackup({ env: env({ BACKUP_NOTIFY_EMAIL: undefined }), email, logger: log, tempDir }),
    ).resolves.toBe('config_missing');
    await expect(
      runBackup({ env: env({ BACKUP_ENCRYPTION_KEY: undefined }), email, tempDir }),
    ).resolves.toBe('config_missing');

    expect(process.exitCode).toBe(1);
    expect(execFileMock).not.toHaveBeenCalled();
    expect(await leftovers()).toEqual([]);
    expect(email.backups).toHaveLength(0);
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ phase: 'config', missing: ['BACKUP_NOTIFY_EMAIL'] }),
      expect.any(String),
    );
  });
});

describe('sealDump and openDump', () => {
  it('round-trips through a random iv and rejects a wrong key or a damaged file', () => {
    const first = sealDump(DUMP, KEY);

    expect(first.equals(sealDump(DUMP, KEY))).toBe(false);
    expect(openDump(first, KEY).equals(DUMP)).toBe(true);
    expect(() => openDump(first, Buffer.alloc(32, 9))).toThrow();
    expect(() => openDump(tamperedSeal(DUMP, KEY), KEY)).toThrow();
    expect(() => openDump(first.subarray(0, 20), KEY)).toThrow();
  });
});

describe('isPgDumpArchive', () => {
  it('accepts the pg_dump magic and nothing else', () => {
    expect(isPgDumpArchive(DUMP)).toBe(true);
    expect(isPgDumpArchive(Buffer.from('-- PostgreSQL database dump'))).toBe(false);
    expect(isPgDumpArchive(Buffer.alloc(0))).toBe(false);
  });
});

describe('pgConnectionEnv', () => {
  it('maps the URL onto libpq variables and decodes percent-escaped credentials', () => {
    expect(
      pgConnectionEnv(
        'postgresql://kfa%20app:p%40ss%3Aword@db.internal:5432/kfa?sslmode=verify-full',
      ),
    ).toEqual({
      PGHOST: 'db.internal',
      PGPORT: '5432',
      PGUSER: 'kfa app',
      PGPASSWORD: 'p@ss:word',
      PGDATABASE: 'kfa',
      PGSSLMODE: 'verify-full',
    });
  });

  it('omits what the URL does not carry', () => {
    expect(pgConnectionEnv('postgresql:///kfa')).toEqual({ PGDATABASE: 'kfa' });
  });
});
