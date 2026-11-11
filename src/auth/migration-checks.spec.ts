import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// JS RegExp and PostgreSQL POSIX regex (`column ~ 'pattern'`) agree for these simple anchored classes.
const MIGRATION_PATH = join(
  __dirname,
  '..',
  '..',
  'prisma',
  'migrations',
  '20261029120000_auth_foundation',
  'migration.sql',
);

// Matches `CHECK ("col" ~ '<regex>')` and the nullable `CHECK ("col" IS NULL OR "col" ~ '<regex>')` form.
const CHECK_PATTERN = /CONSTRAINT "([\w-]+)" CHECK \("(\w+)" (?:IS NULL OR "\2" )?~ '([^']*)'\)/g;

const HASH_COLUMNS = ['device_key_hash', 'ua_hash', 'ip_hash', 'token_hash'];
const REGEX_COLUMNS = ['phone', 'username', ...HASH_COLUMNS];

function extractCheckPatterns(sql: string): Map<string, string> {
  const patterns = new Map<string, string>();
  for (const [, , column, pattern] of sql.matchAll(CHECK_PATTERN)) {
    if (column !== undefined && pattern !== undefined) patterns.set(column, pattern);
  }
  return patterns;
}

const checkPatterns = extractCheckPatterns(readFileSync(MIGRATION_PATH, 'utf8'));

function checkRegex(column: string): RegExp {
  const pattern = checkPatterns.get(column);
  if (pattern === undefined) throw new Error(`migration has no CHECK regex for column "${column}"`);
  return new RegExp(pattern);
}

describe('auth foundation migration CHECK regexes', () => {
  it('declares every format constraint as an anchored class without backslash escapes', () => {
    expect([...checkPatterns.keys()].sort()).toEqual([
      'device_key_hash',
      'ip_hash',
      'phone',
      'token_hash',
      'ua_hash',
      'username',
    ]);

    for (const column of REGEX_COLUMNS) {
      const source = checkRegex(column).source;
      // A backslash in the SQL literal would be a literal backslash to PostgreSQL (standard_conforming_strings).
      expect(source).not.toContain('\\');
      expect(source.startsWith('^')).toBe(true);
      expect(source.endsWith('$')).toBe(true);
    }
  });

  describe('users_phone_format_check', () => {
    it.each(['+14155552671', '+989123456789', '+123456789012345'])(
      'accepts E.164 number %s',
      (value) => expect(checkRegex('phone').test(value)).toBe(true),
    );

    it.each([
      '123',
      '14155552671',
      '+0123456789',
      '\\+14155552671',
      '+1 415 555 2671',
      '+1415555267123456',
    ])('rejects %s', (value) => expect(checkRegex('phone').test(value)).toBe(false));
  });

  describe('users_username_format_check', () => {
    it('accepts abc_12', () => expect(checkRegex('username').test('abc_12')).toBe(true));

    it.each(['Ab', 'a', 'bad name', 'a'.repeat(31)])('rejects %s', (value) =>
      expect(checkRegex('username').test(value)).toBe(false),
    );
  });

  for (const column of HASH_COLUMNS) {
    describe(`${column} format check`, () => {
      it('accepts 64 lowercase hex characters', () =>
        expect(checkRegex(column).test('9f'.repeat(32))).toBe(true));

      it.each([
        ['63 characters', '9f'.repeat(32).slice(1)],
        ['uppercase hex', '9F'.repeat(32)],
        ['non-hex characters', '9g'.repeat(32)],
      ])('rejects %s', (_label, value) => expect(checkRegex(column).test(value)).toBe(false));
    });
  }
});

// ---------------------------------------------------------------------------
// Stage 3.2c: the step-up stamp the re-authentication guard reads.
// ---------------------------------------------------------------------------

const STEPUP_MIGRATION_PATH = join(
  __dirname,
  '..',
  '..',
  'prisma',
  'migrations',
  '20261105120000_session_stepup',
  'migration.sql',
);

const stepupSql = readFileSync(STEPUP_MIGRATION_PATH, 'utf8');

describe('session step-up migration', () => {
  it('adds exactly one nullable timestamp column', () => {
    const statements = stepupSql
      // Comment lines describe the change; they are not executed.
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('--'))
      .join('\n')
      .split(';')
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0);

    expect(statements).toEqual(['ALTER TABLE "sessions" ADD COLUMN "stepup_at" TIMESTAMPTZ(6)']);

    // Nullable on purpose: a session that never stepped up must stay valid for
    // every other route.
    expect(statements[0]).not.toContain('NOT NULL');
    expect(statements[0]).not.toContain('DEFAULT');
  });

  it('needs no grant change: a new column inherits the table privileges', () => {
    expect(stepupSql).not.toMatch(/\bGRANT\b|\bREVOKE\b/i);
  });

  it('uses no escaped backslash', () => {
    expect(stepupSql).not.toContain('\\\\');
  });
});

// ---------------------------------------------------------------------------
// E2-a: email/password identity columns. Phone stays; it only becomes optional.
// ---------------------------------------------------------------------------

const EMAIL_MIGRATION_PATH = join(
  __dirname,
  '..',
  '..',
  'prisma',
  'migrations',
  '20261111120000_email_password_columns',
  'migration.sql',
);

const emailSql = readFileSync(EMAIL_MIGRATION_PATH, 'utf8');
const emailPatterns = extractCheckPatterns(emailSql);

/** `CHECK ("col" IS NULL OR char_length("col") <= N)` and the BETWEEN form. */
const LENGTH_CHECK_PATTERN =
  /CONSTRAINT "[\w-]+" CHECK \("\w+" IS NULL OR char_length\("(\w+)"\) (?:<= (\d+)|BETWEEN (\d+) AND (\d+))\)/g;

interface LengthCheck {
  readonly min: number;
  readonly max: number;
}

function extractLengthChecks(sql: string): Map<string, LengthCheck> {
  const checks = new Map<string, LengthCheck>();
  for (const [, column, maxOnly, min, max] of sql.matchAll(LENGTH_CHECK_PATTERN)) {
    if (column === undefined) continue;
    checks.set(
      column,
      maxOnly === undefined
        ? { min: Number(min), max: Number(max) }
        : { min: 0, max: Number(maxOnly) },
    );
  }
  return checks;
}

const emailLengthChecks = extractLengthChecks(emailSql);

function emailRegex(): RegExp {
  const pattern = emailPatterns.get('email');
  if (pattern === undefined) throw new Error('migration has no CHECK regex for column "email"');
  return new RegExp(pattern);
}

describe('email/password migration', () => {
  it('adds exactly the three identity columns, all nullable', () => {
    expect(emailSql).toMatch(/ADD COLUMN "email" TEXT\b/);
    expect(emailSql).toMatch(/ADD COLUMN "password_hash" TEXT\b/);
    expect(emailSql).toMatch(/ADD COLUMN "email_verified_at" TIMESTAMPTZ\(6\)/);

    const added = emailSql.split('\n').filter((line) => line.includes('ADD COLUMN'));
    expect(added).toHaveLength(3);
    for (const line of added) expect(line).not.toContain('NOT NULL');
  });

  it('makes phone optional without dropping the column or its index', () => {
    expect(emailSql).toMatch(/ALTER COLUMN "phone" DROP NOT NULL/);
    expect(emailSql).not.toMatch(/DROP COLUMN/i);
    expect(emailSql).not.toMatch(/DROP INDEX|DROP CONSTRAINT/i);
  });

  it('creates the email unique index under the name Prisma derives from @unique', () => {
    expect(emailSql).toMatch(/CREATE UNIQUE INDEX "users_email_key" ON "users"\("email"\)/);
  });

  it('needs no grant change: table-level grants cover a new column', () => {
    expect(emailSql).not.toMatch(/\bGRANT\b|\bREVOKE\b/i);
  });

  it('declares the email format as the only regex constraint, anchored and backslash-free', () => {
    expect([...emailPatterns.keys()].sort()).toEqual(['email']);

    const source = emailRegex().source;
    // A backslash in the SQL literal would be a literal backslash to PostgreSQL (standard_conforming_strings).
    expect(source).not.toContain('\\');
    expect(source.startsWith('^')).toBe(true);
    expect(source.endsWith('$')).toBe(true);
  });

  it('bounds both stored lengths in the database', () => {
    expect(emailLengthChecks.get('email')).toEqual({ min: 0, max: 254 });
    expect(emailLengthChecks.get('password_hash')).toEqual({ min: 20, max: 512 });
  });

  describe('users_email_format_check', () => {
    it.each(['ivan.petrov+kfa@example.co.uk', 'a@b.co', 'ivan@xn--80ak6aa92e.com'])(
      'accepts normalized address %s',
      (value) => expect(emailRegex().test(value)).toBe(true),
    );

    it.each([
      ['uppercase local part', 'Ivan@example.com'],
      ['uppercase domain', 'ivan@Example.com'],
      ['space', 'ivan @example.com'],
      ['missing TLD', 'ivan@localhost'],
      ['empty domain label', 'ivan@.com'],
      ['local part over 64 characters', `${'a'.repeat(65)}@example.com`],
    ])('rejects %s', (_label, value) => expect(emailRegex().test(value)).toBe(false));

    it('accepts a 64-character local part', () =>
      expect(emailRegex().test(`${'a'.repeat(64)}@example.com`)).toBe(true));
  });
});
