import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const MIGRATIONS_DIR = join(__dirname, '..', '..', '..', 'prisma', 'migrations');
const MIGRATION = '20261103120000_owner_protection_trigger';
const ROLE_MODEL_MIGRATION = '20261102120000_role_model_identity_verifier';

const sql = readFileSync(join(MIGRATIONS_DIR, MIGRATION, 'migration.sql'), 'utf8');

// Comments and indentation are irrelevant to the shape of the rules.
const code = sql.replace(/--[^\n]*/g, ' ');
const flat = code.replace(/\s+/g, ' ').replace(/\( /g, '(').replace(/ \)/g, ')');

// Everything outside the plpgsql bodies, which legitimately mention row operations.
const statements = code.replace(/\$\$[\s\S]*?\$\$/g, '');

// Real behaviour (kfa_app vs. superuser, including SET ROLE) is proven by the DB tests in part 3.
describe('owner protection migration', () => {
  it('runs after the role model migration', () => {
    const migrations = readdirSync(MIGRATIONS_DIR).sort();

    expect(migrations).toContain(MIGRATION);
    expect(migrations.indexOf(MIGRATION)).toBeGreaterThan(migrations.indexOf(ROLE_MODEL_MIGRATION));
  });

  it('keys the rules on current_user and kfa_app', () => {
    expect(flat).toContain(`IF current_user <> 'kfa_app' THEN`);
    expect(flat).toContain(`IF current_user = 'kfa_app' THEN`);
    expect(sql).not.toContain('session_user');
    expect(sql).toContain('SECURITY INVOKER');
    expect(sql).not.toContain('SECURITY DEFINER');
    expect(sql.match(/SET search_path = pg_catalog/g)).toHaveLength(2);
  });

  it('adds no column, data or privilege changes', () => {
    for (const forbidden of [/\bDROP\b/i, /\bALTER\s+TABLE\b/i, /\bGRANT\b/i, /\bREVOKE\b/i]) {
      expect(sql).not.toMatch(forbidden);
    }

    for (const forbidden of [
      /\bDELETE\s+FROM\b/i,
      /\bINSERT\s+INTO\b/i,
      /\bUPDATE\s+"?users"?/i,
      /\bTRUNCATE\s+"?users"?/i,
    ]) {
      expect(statements).not.toMatch(forbidden);
    }
  });

  it('raises insufficient_privilege from every rejection', () => {
    const raises = sql.match(/RAISE EXCEPTION[^;]*;/g) ?? [];

    expect(raises).toHaveLength(5);
    for (const raise of raises) {
      expect(raise).toContain(`ERRCODE = 'insufficient_privilege'`);
    }
  });

  it('refuses inserting an owner', () => {
    expect(flat).toContain(`TG_OP = 'INSERT' THEN IF NEW."role" = 'OWNER' THEN RAISE EXCEPTION`);
  });

  it('refuses changing the role, status or id of an existing owner', () => {
    expect(flat).toContain(
      `IF OLD."role" = 'OWNER' AND (NEW."role" IS DISTINCT FROM OLD."role" OR NEW."status" IS DISTINCT FROM OLD."status" OR NEW."id" IS DISTINCT FROM OLD."id") THEN RAISE EXCEPTION`,
    );
    expect(sql.match(/IS DISTINCT FROM/g)).toHaveLength(4);
  });

  it('refuses promoting another account to owner', () => {
    expect(flat).toContain(
      `IF NEW."role" = 'OWNER' AND OLD."role" IS DISTINCT FROM 'OWNER' THEN RAISE EXCEPTION`,
    );
  });

  it('refuses deleting the owner', () => {
    expect(flat).toContain(`TG_OP = 'DELETE' THEN IF OLD."role" = 'OWNER' THEN RAISE EXCEPTION`);
  });

  it('lets every other mutation through', () => {
    expect(flat).toContain(`IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW;`);
  });

  it('covers insert, update and delete with a row trigger', () => {
    expect(flat).toContain(
      `BEFORE INSERT OR UPDATE OR DELETE ON "users" FOR EACH ROW EXECUTE FUNCTION public.kfa_users_protect_owner();`,
    );
  });

  it('rejects TRUNCATE with a statement trigger', () => {
    expect(flat).toContain(
      `BEFORE TRUNCATE ON "users" FOR EACH STATEMENT EXECUTE FUNCTION public.kfa_users_reject_truncate();`,
    );
  });
});
