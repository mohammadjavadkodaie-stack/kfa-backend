-- Stage 4.1a: one athlete profile per user.
--
-- The profile is written by the user who owns it, so `user_id` is the natural
-- key and the row disappears with the account (ON DELETE CASCADE). No national
-- ID, no address: those belong to a later, separately justified step. The CHECKs
-- below are the last line of defence behind the future request validation, and
-- they use plain character classes (no counted repetition above 255, which
-- PostgreSQL refuses with SQLSTATE 2201B).

CREATE TYPE "Gender" AS ENUM ('FEMALE', 'MALE', 'OTHER', 'UNDISCLOSED');

CREATE TABLE "athlete_profiles" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "legal_first_name" TEXT NOT NULL,
    "legal_last_name" TEXT NOT NULL,
    "date_of_birth" DATE NOT NULL,
    "gender" "Gender" NOT NULL,
    "nationality" VARCHAR(2) NOT NULL,
    "country_of_residence" VARCHAR(2) NOT NULL,
    "city" TEXT NOT NULL,
    "club_name" TEXT,
    "weight_kg" INTEGER,
    "height_cm" INTEGER,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    CONSTRAINT "athlete_profiles_pkey" PRIMARY KEY ("id"),
    -- btrim() so a name of spaces counts as empty, not as a 3-character name.
    CONSTRAINT "athlete_profiles_legal_first_name_length_check" CHECK (length(btrim("legal_first_name")) BETWEEN 1 AND 100),
    CONSTRAINT "athlete_profiles_legal_last_name_length_check" CHECK (length(btrim("legal_last_name")) BETWEEN 1 AND 100),
    CONSTRAINT "athlete_profiles_city_length_check" CHECK (length(btrim("city")) BETWEEN 1 AND 100),
    CONSTRAINT "athlete_profiles_club_name_length_check" CHECK ("club_name" IS NULL OR length(btrim("club_name")) BETWEEN 1 AND 120),
    CONSTRAINT "athlete_profiles_nationality_format_check" CHECK ("nationality" ~ '^[A-Z]{2}$'),
    CONSTRAINT "athlete_profiles_country_of_residence_format_check" CHECK ("country_of_residence" ~ '^[A-Z]{2}$'),
    -- A birth date can never be in the future; the floor keeps junk out of age groups.
    CONSTRAINT "athlete_profiles_date_of_birth_range_check" CHECK ("date_of_birth" BETWEEN DATE '1900-01-01' AND CURRENT_DATE),
    CONSTRAINT "athlete_profiles_weight_kg_range_check" CHECK ("weight_kg" IS NULL OR "weight_kg" BETWEEN 20 AND 300),
    CONSTRAINT "athlete_profiles_height_cm_range_check" CHECK ("height_cm" IS NULL OR "height_cm" BETWEEN 100 AND 250),
    CONSTRAINT "athlete_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- One profile per user: this is what makes the single-statement upsert safe.
CREATE UNIQUE INDEX "athlete_profiles_user_id_key" ON "athlete_profiles"("user_id");

-- Default privileges in db/roles.sql also grant DELETE on future tables.
-- Deleting a profile belongs to the legal deletion step, so the runtime role
-- gets SELECT, INSERT and UPDATE only. Guarded so the migration also applies in
-- environments where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.athlete_profiles FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.athlete_profiles TO kfa_app';
    END IF;
END
$$;
