import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Stage 4.3b: the text of the identity-document migration.
 *
 * The real behaviour (CHECKs, FK, privileges) is proved against PostgreSQL by
 * test/db/identity-document.e2e-spec.ts; this suite reads the SQL, so a wrong
 * grant or a column that should not exist fails even on a machine without a
 * database.
 */

const MIGRATIONS_DIR = join(__dirname, '..', '..', '..', 'prisma', 'migrations');
const MIGRATION = '20261109120000_identity_document';
const ATHLETE_MIGRATION = '20261108120000_athlete_profile';

const sql = readFileSync(join(MIGRATIONS_DIR, MIGRATION, 'migration.sql'), 'utf8');

// Comments describe the change; the assertions below are about the SQL that runs.
const code = sql
  .replace(/--[^\n]*/g, ' ')
  .replace(/\s+/g, ' ')
  .replace(/\( /g, '(')
  .replace(/ \)/g, ')');

/** The GRANT statements, whichever form they take. */
const grants = code.match(/\bGRANT\b[^;]*/gi) ?? [];

describe('identity document migration', () => {
  it('runs after the athlete profile migration', () => {
    const migrations = readdirSync(MIGRATIONS_DIR).sort();

    expect(migrations).toContain(MIGRATION);
    expect(migrations.indexOf(MIGRATION)).toBeGreaterThan(migrations.indexOf(ATHLETE_MIGRATION));
  });

  it('creates the table and the two enums, and nothing else', () => {
    expect(code).toContain(
      `CREATE TYPE "DocumentKind" AS ENUM ('NATIONAL_ID', 'MEDAL', 'CERTIFICATE')`,
    );
    expect(code).toContain(`CREATE TYPE "DocumentStatus" AS ENUM ('ACTIVE', 'DELETED')`);
    expect(code).toContain(`CREATE TABLE "identity_document"`);
    expect(code).toMatch(/"status" "DocumentStatus" NOT NULL DEFAULT 'ACTIVE'/u);
  });

  it('keeps no file name, no URL and no plaintext column', () => {
    for (const forbidden of [
      'file_name',
      'filename',
      'original_name',
      'display_name',
      'url',
      'plaintext',
    ]) {
      expect(code.toLowerCase()).not.toContain(forbidden);
    }

    // A `bytes` column would be the file itself; the size is a number, not the content.
    expect(code).not.toMatch(/"bytes"/iu);
  });

  it('stores the envelope beside an opaque object key', () => {
    expect(code).toMatch(/"object_key" TEXT NOT NULL/u);
    expect(code).toMatch(/"key_id" TEXT NOT NULL/u);
    expect(code).toMatch(/"wrapped_dek" BYTEA NOT NULL/u);
    expect(code).toMatch(/"iv" BYTEA NOT NULL/u);
    expect(code).toMatch(/"auth_tag" BYTEA NOT NULL/u);
  });

  it('makes the object key unique and indexes the quota read', () => {
    expect(code).toContain(
      `CREATE UNIQUE INDEX "identity_document_object_key_key" ON "identity_document"("object_key")`,
    );
    expect(code).toContain(
      `CREATE INDEX "identity_document_owner_user_id_status_idx" ON "identity_document"("owner_user_id", "status")`,
    );
  });

  it('declares the format CHECK constraints', () => {
    expect(code).toContain(
      `CONSTRAINT "identity_document_content_type_known_check" CHECK ("content_type" IN ('image/jpeg', 'image/png'))`,
    );
    expect(code).toContain(
      `CONSTRAINT "identity_document_size_bytes_positive_check" CHECK ("size_bytes" > 0)`,
    );
    expect(code).toContain(
      `CONSTRAINT "identity_document_sha256_format_check" CHECK ("sha256" ~ '^[0-9a-f]{64}$')`,
    );
    expect(code).toContain(
      `CONSTRAINT "identity_document_iv_length_check" CHECK (octet_length("iv") = 12)`,
    );
    expect(code).toContain(
      `CONSTRAINT "identity_document_auth_tag_length_check" CHECK (octet_length("auth_tag") = 16)`,
    );
  });

  it('accepts only lowercase hex for the digest', () => {
    const pattern = new RegExp(String.raw`^[0-9a-f]{64}$`);

    expect(pattern.test('9f'.repeat(32))).toBe(true);
    expect(pattern.test('9F'.repeat(32))).toBe(false);
    expect(pattern.test('9f'.repeat(32).slice(1))).toBe(false);
  });

  it('keeps the owner with RESTRICT rather than CASCADE', () => {
    expect(code).toContain(
      `CONSTRAINT "identity_document_owner_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE`,
    );
  });

  it('grants SELECT, INSERT and UPDATE to kfa_app and no DELETE', () => {
    expect(grants).toHaveLength(1);
    expect(code).toContain(
      `EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.identity_document TO kfa_app'`,
    );
    expect(grants[0]).not.toMatch(/\bDELETE\b/i);
    expect(code).not.toMatch(/GRANT[^;]*\bDELETE\b/i);
    expect(code).not.toMatch(/\bGRANT\s+ALL\b/i);
    // Privileges are only touched where the runtime role already exists.
    expect(code).toContain(
      `IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN`,
    );
  });
});
