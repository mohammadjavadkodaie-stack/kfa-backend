-- Stage 1: append-only, tamper-evident audit log.
--
-- Hand-written on purpose. Prisma cannot express plpgsql triggers or the
-- privilege split, so those parts are authored here and reviewed like code.
-- Apply with `pnpm prisma migrate deploy` (connects as kfa_migrator).

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------

CREATE TABLE "audit_log" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "actor_id" UUID,
    "actor_role" TEXT,
    "action" TEXT NOT NULL,
    "target_type" TEXT,
    "target_id" TEXT,
    "request_id" TEXT,
    "ip_hash" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}'::JSONB,
    "prev_hash" TEXT,
    "hash" TEXT NOT NULL,

    CONSTRAINT "audit_log_pkey" PRIMARY KEY ("id"),
    -- Format checks are defence in depth for the hash chain: a row can never be
    -- written with a truncated/forged-looking digest, even by mistake.
    CONSTRAINT "audit_log_action_not_empty_check" CHECK (length("action") > 0),
    CONSTRAINT "audit_log_hash_format_check" CHECK ("hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "audit_log_prev_hash_format_check" CHECK (
        "prev_hash" IS NULL OR "prev_hash" ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT "audit_log_ip_hash_format_check" CHECK (
        "ip_hash" IS NULL OR "ip_hash" ~ '^[0-9a-f]{64}$'
    )
);

CREATE UNIQUE INDEX "audit_log_hash_key" ON "audit_log"("hash");
CREATE INDEX "audit_log_created_at_idx" ON "audit_log"("created_at");
CREATE INDEX "audit_log_actor_id_idx" ON "audit_log"("actor_id");
CREATE INDEX "audit_log_action_idx" ON "audit_log"("action");

COMMENT ON TABLE "audit_log" IS
    'Append-only audit trail. UPDATE, DELETE and TRUNCATE are rejected by triggers; runtime role has SELECT/INSERT only.';
COMMENT ON COLUMN "audit_log"."hash" IS
    'sha256(prev_hash || canonical JSON of the immutable row fields)';
COMMENT ON COLUMN "audit_log"."prev_hash" IS
    'hash of the previous row in the chain (NULL for the first row)';
COMMENT ON COLUMN "audit_log"."ip_hash" IS
    'HMAC-SHA256 of the client IP; the raw IP is never stored';

-- ---------------------------------------------------------------------------
-- Append-only enforcement (row-level UPDATE/DELETE, statement-level TRUNCATE)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.kfa_audit_log_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is forbidden', TG_OP
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Insert a new audit row instead of modifying history.';
END;
$$;

CREATE TRIGGER "audit_log_no_update"
BEFORE UPDATE ON "audit_log"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_audit_log_reject_mutation();

CREATE TRIGGER "audit_log_no_delete"
BEFORE DELETE ON "audit_log"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_audit_log_reject_mutation();

CREATE TRIGGER "audit_log_no_truncate"
BEFORE TRUNCATE ON "audit_log"
FOR EACH STATEMENT
EXECUTE FUNCTION public.kfa_audit_log_reject_mutation();

-- Nobody gets blanket access through PUBLIC; the runtime role gets the minimum.
REVOKE ALL ON TABLE "audit_log" FROM PUBLIC;

-- Default privileges in db/roles.sql grant UPDATE/DELETE on future tables.
-- audit_log must be the exception: SELECT + INSERT only. Guarded so the
-- migration also works in environments where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.audit_log FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.audit_log TO kfa_app';
    END IF;
END
$$;
