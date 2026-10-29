-- Stage 3.2: TOTP second factor. Same grants as every other table owned by
-- kfa_migrator (db/roles.sql defaults), so no GRANT/REVOKE here.

CREATE TABLE "totp_credentials" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "secret_enc" TEXT NOT NULL,
    "confirmed_at" TIMESTAMPTZ(6),
    "last_used_step" BIGINT NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    CONSTRAINT "totp_credentials_pkey" PRIMARY KEY ("id"),
    -- Only the ciphertext envelope is stored, so the version tag is part of the format.
    CONSTRAINT "totp_credentials_secret_enc_format_check" CHECK ("secret_enc" ~ '^v1[A-Za-z0-9+/=:._-]{8,8000}$'),
    CONSTRAINT "totp_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- One credential per user.
CREATE UNIQUE INDEX "totp_credentials_user_id_key" ON "totp_credentials"("user_id");

CREATE TABLE "recovery_codes" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    CONSTRAINT "recovery_codes_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "recovery_codes_code_hash_format_check" CHECK ("code_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "recovery_codes_user_id_code_hash_key" UNIQUE ("user_id", "code_hash"),
    CONSTRAINT "recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "recovery_codes_user_id_idx" ON "recovery_codes"("user_id");
