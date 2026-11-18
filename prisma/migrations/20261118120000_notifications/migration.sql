-- In-site notifications: one row per thing the owner should see in the app.
--
-- No free text is stored: `kind` is a closed enum and `params` holds enum
-- values only, so every sentence is rendered by the client from its message
-- catalog and no server string can reach the page. Nothing identifying is
-- copied into a row - the owner is the row's only subject.

CREATE TYPE "NotificationKind" AS ENUM (
    'profile_under_review',
    'profile_approved',
    'profile_rejected',
    'upload_status',
    'subscription_status'
);

CREATE TABLE "notifications" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "kind" "NotificationKind" NOT NULL,
    "params" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "read_at" TIMESTAMPTZ(6),

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "notifications_params_object_check" CHECK (jsonb_typeof("params") = 'object'),
    CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id")
        REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- The inbox reads newest first and counts unread per owner.
CREATE INDEX "notifications_user_id_created_at_idx"
    ON "notifications"("user_id", "created_at" DESC);
CREATE INDEX "notifications_user_id_read_at_idx" ON "notifications"("user_id", "read_at");

-- Least privilege: the runtime role may append rows and read them, and may only
-- ever stamp read_at - never rewrite a row and never delete one (a notification
-- is not a client-managed row; a purge path, if wanted, is a later feature).
-- Guarded, because the roles are created by db/roles.sql, not by this migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE "notifications" FROM PUBLIC, kfa_app';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE "notifications" TO kfa_app';
        EXECUTE 'GRANT UPDATE ("read_at") ON TABLE "notifications" TO kfa_app';
    END IF;
END
$$;