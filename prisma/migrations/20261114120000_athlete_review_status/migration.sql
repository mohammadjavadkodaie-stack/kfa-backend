CREATE TYPE "ReviewStatus" AS ENUM ('DRAFT', 'PENDING', 'APPROVED', 'REJECTED');

ALTER TABLE "athlete_profiles"
  ADD COLUMN "review_status" "ReviewStatus" NOT NULL DEFAULT 'DRAFT',
  ADD COLUMN "submitted_at" TIMESTAMPTZ(6),
  ADD COLUMN "reviewed_at" TIMESTAMPTZ(6),
  ADD COLUMN "reviewed_by_id" UUID,
  ADD COLUMN "rejection_reason" VARCHAR(500);