import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Same approach as migration-checks.spec.ts, scoped to the stage 3.2 TOTP tables.
const MIGRATION_PATH = join(
  __dirname,
  '..',
  '..',
  'prisma',
  'migrations',
  '20261104120000_totp_credentials',
  'migration.sql',
);

// Matches `CHECK ("col" ~ '<regex>')` and the nullable `CHECK ("col" IS NULL OR "col" ~ '<regex>')` form.
const CHECK_PATTERN = /CONSTRAINT "([\w-]+)" CHECK \("(\w+)" (?:IS NULL OR "\2" )?~ '([^']*)'\)/g;

const sql = readFileSync(MIGRATION_PATH, 'utf8');

function checkRegex(column: string): RegExp {
  for (const [, , checked, pattern] of sql.matchAll(CHECK_PATTERN)) {
    if (checked === column && pattern !== undefined) return new RegExp(pattern);
  }
  throw new Error(`migration has no CHECK regex for column "${column}"`);
}

describe('totp credentials migration CHECK regexes', () => {
  it('declares only the expected format constraints', () => {
    const columns = [...sql.matchAll(CHECK_PATTERN)].map(([, , column]) => column).sort();
    expect(columns).toEqual(['code_hash', 'secret_enc']);
  });

  it('uses no escaped backslash', () => {
    // PostgreSQL reads `\\` in a standard_conforming_strings literal as two backslashes.
    expect(sql).not.toContain('\\\\');
    expect(checkRegex('code_hash').source).not.toContain('\\');
    expect(checkRegex('secret_enc').source).not.toContain('\\');
  });

  describe('recovery_codes_code_hash_format_check', () => {
    it('accepts 64 lowercase hex characters', () =>
      expect(checkRegex('code_hash').test('9f'.repeat(32))).toBe(true));

    it.each([
      ['63 characters', '9f'.repeat(32).slice(1)],
      ['65 characters', `${'9f'.repeat(32)}0`],
      ['uppercase hex', '9F'.repeat(32)],
      ['non-hex characters', '9g'.repeat(32)],
    ])('rejects %s', (_label, value) => expect(checkRegex('code_hash').test(value)).toBe(false));
  });

  describe('totp_credentials_secret_enc_format_check', () => {
    it('accepts a v1 envelope', () =>
      expect(checkRegex('secret_enc').test(`v1:${'A1b2+/='.repeat(6)}`)).toBe(true));

    it.each([
      ['a bare base32 secret', 'JBSWY3DPEHPK3PXP'],
      ['another version tag', `v2:${'A1b2+/='.repeat(6)}`],
      ['an envelope that is too short', 'v1abc'],
      ['characters outside the class', `v1:${'A1b2'.repeat(4)} %`],
    ])('rejects %s', (_label, value) => expect(checkRegex('secret_enc').test(value)).toBe(false));
  });
});
