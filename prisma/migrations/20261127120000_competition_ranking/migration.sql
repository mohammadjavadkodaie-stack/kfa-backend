-- Stage 8a: staff-entered competition results and the derived ranking.
--
-- `competition_results` is the only place a score exists; it is written by a
-- staff route only. `athlete_rankings` is derived, recomputed in the same
-- transaction as every change, and never written from a client. Both sides
-- cascade, so removing a profile takes its results and its ranking row with it.
--
-- Generated with `prisma migrate diff` (no database was contacted); the CHECK
-- and the grants below are appended by hand. The points CHECK is the last line
-- of defence behind the DTO's 0..1000 bound: a value outside it cannot be
-- stored at all.
--
-- CreateTable
CREATE TABLE "competition_results" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "athlete_profile_id" UUID NOT NULL,
    "event_name" VARCHAR(120) NOT NULL,
    "event_date" DATE NOT NULL,
    "points" INTEGER NOT NULL,
    "entered_by_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "competition_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "athlete_rankings" (
    "athlete_profile_id" UUID NOT NULL,
    "total_points" INTEGER NOT NULL,
    "rank" INTEGER NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "athlete_rankings_pkey" PRIMARY KEY ("athlete_profile_id")
);

-- CreateIndex
CREATE INDEX "competition_results_athlete_profile_id_idx" ON "competition_results"("athlete_profile_id");

-- CreateIndex
CREATE INDEX "athlete_rankings_total_points_idx" ON "athlete_rankings"("total_points" DESC);

-- AddForeignKey
ALTER TABLE "competition_results" ADD CONSTRAINT "competition_results_athlete_profile_id_fkey" FOREIGN KEY ("athlete_profile_id") REFERENCES "athlete_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "competition_results" ADD CONSTRAINT "competition_results_entered_by_id_fkey" FOREIGN KEY ("entered_by_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "athlete_rankings" ADD CONSTRAINT "athlete_rankings_athlete_profile_id_fkey" FOREIGN KEY ("athlete_profile_id") REFERENCES "athlete_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- The score range lives in the database as well as in the DTO.
ALTER TABLE "competition_results"
    ADD CONSTRAINT "competition_results_points_range_check" CHECK ("points" BETWEEN 0 AND 1000);

-- The runtime role needs full row CRUD here: a staff member may correct or
-- withdraw a result, and the ranking rows are rewritten on every recompute. The
-- default privileges in db/roles.sql would grant this anyway; the explicit
-- statements keep the migration self-contained. Guarded so it also applies where
-- the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.competition_results, public.athlete_rankings FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.competition_results, public.athlete_rankings TO kfa_app';
    END IF;
END
$$;

