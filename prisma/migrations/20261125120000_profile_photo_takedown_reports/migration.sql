-- Stage 7b-3: admin takedown of a profile photo and user reports.
--
-- Two additions:
-- 1. `REMOVED` on the photo status enum. A takedown is not a review outcome:
--    an APPROVED photo can be withdrawn from public view, and the row stays in
--    place (the encrypted blob is untouched, retention is a later step).
-- 2. `photo_reports`, append-only: one row per (photo, reporter), a fixed reason
--    code and an optional short note. The unique pair makes a duplicate report a
--    no-op at the database, not only in the service.

-- CreateEnum
CREATE TYPE "PhotoReportReason" AS ENUM ('SPAM', 'ABUSE', 'NUDITY', 'OTHER');


-- AlterEnum
ALTER TYPE "ProfilePhotoStatus" ADD VALUE 'REMOVED';

-- CreateTable
CREATE TABLE "photo_reports" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "photo_id" UUID NOT NULL,
    "reporter_user_id" UUID NOT NULL,
    "reason" "PhotoReportReason" NOT NULL,
    "note" VARCHAR(200),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "photo_reports_pkey" PRIMARY KEY ("id"),
    -- The API stores a trimmed, control-free note; this is the last line of defence.
    CONSTRAINT "photo_reports_note_sanitized_check" CHECK (
        "note" IS NULL OR ("note" = btrim("note") AND "note" !~ '[[:cntrl:]]')
    )
);

-- CreateIndex
CREATE INDEX "photo_reports_photo_id_created_at_idx" ON "photo_reports"("photo_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "photo_reports_photo_id_reporter_user_id_key" ON "photo_reports"("photo_id", "reporter_user_id");

-- AddForeignKey
ALTER TABLE "photo_reports" ADD CONSTRAINT "photo_reports_photo_id_fkey" FOREIGN KEY ("photo_id") REFERENCES "profile_photos"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "photo_reports" ADD CONSTRAINT "photo_reports_reporter_user_id_fkey" FOREIGN KEY ("reporter_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- A report is append-only for the runtime role: it may read and add reports,
-- never rewrite or delete one. profile_photos stays without DELETE as well
-- (granted SELECT, INSERT, UPDATE only by the 7a migration and db/roles.sql).
-- Guarded so the migration also applies where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.photo_reports FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.photo_reports TO kfa_app';
    END IF;
END
$$;
