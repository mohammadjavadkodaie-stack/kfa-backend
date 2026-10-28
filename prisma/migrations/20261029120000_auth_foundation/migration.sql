-- Stage 2: auth data foundation. Audit_log remains the only append-only table.

CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'BLOCKED');
CREATE TYPE "Role" AS ENUM ('USER', 'ATHLETE', 'ADMIN', 'OWNER', 'IDENTITY_VERIFIER');

CREATE TABLE "users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "phone" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "status" "UserStatus" NOT NULL DEFAULT 'ACTIVE',
    "phone_verified_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    CONSTRAINT "users_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "users_phone_format_check" CHECK ("phone" ~ '^\\+[1-9][0-9]{6,14}$'),
    CONSTRAINT "users_username_format_check" CHECK ("username" ~ '^[a-z0-9_]{3,30}$')
);
CREATE UNIQUE INDEX "users_phone_key" ON "users"("phone");
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

CREATE TABLE "devices" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "device_key_hash" TEXT NOT NULL,
    "ua_hash" TEXT,
    "label" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "revoked_at" TIMESTAMPTZ(6),
    CONSTRAINT "devices_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "devices_key_hash_format_check" CHECK ("device_key_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "devices_ua_hash_format_check" CHECK ("ua_hash" IS NULL OR "ua_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "devices_label_length_check" CHECK ("label" IS NULL OR length("label") <= 100),
    CONSTRAINT "devices_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "devices_device_key_hash_key" ON "devices"("device_key_hash");
CREATE INDEX "devices_user_id_idx" ON "devices"("user_id");

CREATE TABLE "sessions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "last_used_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "revoked_at" TIMESTAMPTZ(6),
    "revoked_reason" TEXT,
    "ip_hash" TEXT,
    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "sessions_revoked_reason_length_check" CHECK ("revoked_reason" IS NULL OR length("revoked_reason") <= 100),
    CONSTRAINT "sessions_ip_hash_format_check" CHECK ("ip_hash" IS NULL OR "ip_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "sessions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");
CREATE INDEX "sessions_device_id_idx" ON "sessions"("device_id");
CREATE INDEX "sessions_expires_at_idx" ON "sessions"("expires_at");

CREATE TABLE "refresh_tokens" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "session_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "refresh_tokens_hash_format_check" CHECK ("token_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "refresh_tokens_token_hash_key" ON "refresh_tokens"("token_hash");
CREATE INDEX "refresh_tokens_session_id_idx" ON "refresh_tokens"("session_id");
CREATE INDEX "refresh_tokens_expires_at_idx" ON "refresh_tokens"("expires_at");
