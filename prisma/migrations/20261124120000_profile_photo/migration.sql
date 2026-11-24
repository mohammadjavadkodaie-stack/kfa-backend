-- Stage 7a: photos on the athlete's personal page.
--
-- The row keeps only what is needed to find one encrypted blob again: an opaque
-- object key, the envelope that unwraps its data key, and the digest of the
-- bytes the scanner approved. There is no file name, no URL and no plaintext
-- column. New rows are always PENDING: the CHECK constraints refuse a row that
-- claims a decision without a reviewer and a time, and the withheld DELETE
-- privilege keeps removal for a later retention step.

CREATE TYPE "ProfilePhotoStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

CREATE TABLE "profile_photos" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "athlete_profile_id" UUID NOT NULL,
    -- randomUUID() from createObjectKey(): never a user id, a file name or an extension.
    "object_key" TEXT NOT NULL,
    -- Already sanitized, escaped and capped by the API; TEXT plus the CHECK below
    -- would be equivalent, but the column states the limit it enforces.
    "caption" VARCHAR(1000),
    "status" "ProfilePhotoStatus" NOT NULL DEFAULT 'PENDING',
    "content_type" TEXT NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "sha256" CHAR(64) NOT NULL,
    "key_id" TEXT NOT NULL,
    "wrapped_dek" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "auth_tag" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "reviewed_at" TIMESTAMPTZ(6),
    "reviewed_by_id" UUID,
    CONSTRAINT "profile_photos_pkey" PRIMARY KEY ("id"),
    -- The ingest pipeline only ever hands back these two formats.
    CONSTRAINT "profile_photos_content_type_known_check" CHECK ("content_type" IN ('image/jpeg', 'image/png')),
    CONSTRAINT "profile_photos_size_bytes_positive_check" CHECK ("size_bytes" > 0),
    CONSTRAINT "profile_photos_sha256_format_check" CHECK ("sha256" ~ '^[0-9a-f]{64}$'),
    -- AES-256-GCM geometry: a wrapped key blob of any length would be unreadable.
    CONSTRAINT "profile_photos_iv_length_check" CHECK (octet_length("iv") = 12),
    CONSTRAINT "profile_photos_auth_tag_length_check" CHECK (octet_length("auth_tag") = 16),
    -- The API stores trimmed, control-free, markup-free text; the CHECK is the
    -- last line of defence behind the caption schema.
    CONSTRAINT "profile_photos_caption_sanitized_check" CHECK (
        "caption" IS NULL
        OR (
            "caption" = btrim("caption")
            AND "caption" !~ '[[:cntrl:]]'
            AND "caption" !~ '[<>]'
        )
    ),
    -- PENDING has no decision; a decided row has both a reviewer and a time.
    CONSTRAINT "profile_photos_review_state_check" CHECK (
        ("status" = 'PENDING' AND "reviewed_at" IS NULL AND "reviewed_by_id" IS NULL)
        OR ("status" <> 'PENDING' AND "reviewed_at" IS NOT NULL AND "reviewed_by_id" IS NOT NULL)
    ),
    -- A photo belongs to the profile; removing the profile removes its photos.
    CONSTRAINT "profile_photos_athlete_profile_id_fkey" FOREIGN KEY ("athlete_profile_id") REFERENCES "athlete_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- One blob per object key, so a copied key is caught by the database and not
-- only by the storage layer.
CREATE UNIQUE INDEX "profile_photos_object_key_key" ON "profile_photos"("object_key");

-- The quota counts the not-rejected rows of one profile; this index is exactly
-- that shape, so the check stays cheap as the table grows.
CREATE INDEX "profile_photos_athlete_profile_id_status_idx" ON "profile_photos"("athlete_profile_id", "status");

-- The owner's list reads newest first per profile.
CREATE INDEX "profile_photos_athlete_profile_id_created_at_idx" ON "profile_photos"("athlete_profile_id", "created_at" DESC);

-- Default privileges in db/roles.sql also grant DELETE on future tables.
-- Deleting a photo belongs to a retention step, so the runtime role gets
-- SELECT, INSERT and UPDATE only. Guarded so the migration also applies in
-- environments where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.profile_photos FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.profile_photos TO kfa_app';
    END IF;
END
$$;
