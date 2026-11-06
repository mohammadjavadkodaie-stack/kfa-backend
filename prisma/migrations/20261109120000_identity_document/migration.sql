-- Stage 4.3b: the record behind an uploaded identity document.
--
-- The row keeps only what is needed to find one encrypted blob again: an opaque
-- object key, the envelope that unwraps its data key, and the digest of the bytes
-- the scanner approved. There is deliberately no original file name, no URL and
-- no plaintext column, so the table cannot become a directory of who sent what.
-- The CHECKs are the last line of defence behind the upload service; the sha256
-- pattern uses counted repetition of 64, which PostgreSQL accepts (the SQLSTATE
-- 2201B limit is 255).

CREATE TYPE "DocumentKind" AS ENUM ('NATIONAL_ID', 'MEDAL', 'CERTIFICATE');

CREATE TYPE "DocumentStatus" AS ENUM ('ACTIVE', 'DELETED');

CREATE TABLE "identity_document" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "owner_user_id" UUID NOT NULL,
    "kind" "DocumentKind" NOT NULL,
    -- randomUUID() from createObjectKey(): never a user id, a file name or an extension.
    "object_key" TEXT NOT NULL,
    "content_type" TEXT NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "sha256" CHAR(64) NOT NULL,
    "key_id" TEXT NOT NULL,
    "wrapped_dek" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "auth_tag" BYTEA NOT NULL,
    "status" "DocumentStatus" NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "deleted_at" TIMESTAMPTZ(6),
    CONSTRAINT "identity_document_pkey" PRIMARY KEY ("id"),
    -- The ingest pipeline only ever hands back these two formats.
    CONSTRAINT "identity_document_content_type_known_check" CHECK ("content_type" IN ('image/jpeg', 'image/png')),
    CONSTRAINT "identity_document_size_bytes_positive_check" CHECK ("size_bytes" > 0),
    CONSTRAINT "identity_document_sha256_format_check" CHECK ("sha256" ~ '^[0-9a-f]{64}$'),
    -- AES-256-GCM geometry: a wrapped key blob of any length would be unreadable.
    CONSTRAINT "identity_document_iv_length_check" CHECK (octet_length("iv") = 12),
    CONSTRAINT "identity_document_auth_tag_length_check" CHECK (octet_length("auth_tag") = 16),
    -- RESTRICT, not CASCADE: an account that still holds documents cannot be
    -- removed before the retention step has decided what happens to the blobs.
    CONSTRAINT "identity_document_owner_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- One blob per object key, so a copied key is caught by the database and not
-- only by the storage layer.
CREATE UNIQUE INDEX "identity_document_object_key_key" ON "identity_document"("object_key");

-- The per-owner quota counts the ACTIVE rows of one owner; this index is exactly
-- that shape, so the check stays cheap as the table grows.
CREATE INDEX "identity_document_owner_user_id_status_idx" ON "identity_document"("owner_user_id", "status");

-- Default privileges in db/roles.sql also grant DELETE on future tables.
-- Deleting a document belongs to the retention step, so the runtime role gets
-- SELECT, INSERT and UPDATE only. Guarded so the migration also applies in
-- environments where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.identity_document FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.identity_document TO kfa_app';
    END IF;
END
$$;
