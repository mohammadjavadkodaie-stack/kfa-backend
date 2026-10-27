-- Stage 2: chain-integrity constraints for the audit log.
--
-- Hand-written like the append-only migration: these are partial / expression
-- unique indexes (Prisma's schema language cannot express them) plus a privilege
-- change. Apply with `pnpm prisma migrate deploy` (connects as kfa_migrator).
--
-- Together with the append-only triggers these rules mean the only row the app
-- can add is the single legitimate successor of the current chain head.

-- ---------------------------------------------------------------------------
-- 1. A prev_hash may be claimed by exactly one row: the chain cannot fork.
--    Appending always links to the current head, so a second row pointing at an
--    existing predecessor is history tampering. Partial index because the first
--    row has no predecessor (prev_hash IS NULL, covered by statement 2).
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX "audit_log_prev_hash_key"
    ON "audit_log" ("prev_hash")
    WHERE "prev_hash" IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. Only one genesis row: at most one row may have prev_hash IS NULL.
--    `(true)` is a constant expression, so the unique index allows a single row
--    in the partial set. This makes a second, independent chain impossible, even
--    if the table is emptied outside the application (e.g. by a restore).
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX "audit_log_single_genesis_key"
    ON "audit_log" ((true))
    WHERE "prev_hash" IS NULL;

-- ---------------------------------------------------------------------------
-- 3. Migration history is not application data. db/roles.sql grants kfa_app
--    CRUD on future tables via ALTER DEFAULT PRIVILEGES, which includes
--    _prisma_migrations; that would let a compromised runtime role rewrite which
--    migrations were applied. Revoke it. Guarded so this migration also applies
--    where the runtime role is created later.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public."_prisma_migrations" FROM kfa_app';
    END IF;
END
$$;
