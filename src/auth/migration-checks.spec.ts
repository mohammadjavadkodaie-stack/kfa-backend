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
