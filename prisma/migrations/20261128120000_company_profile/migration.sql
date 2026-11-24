-- Stage 9a: staff-maintained company profiles.
--
-- `companies` holds the identity card of an organizer, sponsor or partner. The
-- public face (slug, display_name, country, kind, description, website_url) and
-- the staff-only legal identity (legal_name and the registry/tax/contact
-- columns) share one row because they are one record; the split is enforced by
-- the route layer, which is staff-only, and by step 9b selecting only the public
-- columns.
--
-- Deletion is soft: `deleted_at` is stamped once and can never be cleared, and
-- the unique slug index deliberately covers retired rows too, so a slug cannot
-- be reused to impersonate a company. The slug itself is immutable after
-- insert. Both rules are triggers below, not only API checks.
--
-- Generated with `prisma migrate diff` (no database was contacted); the CHECK
-- constraints, the triggers and the grants are appended by hand. Every format
-- rule is repeated here as a CHECK, so a future caller that skips the DTO still
-- cannot store a malformed value. The regexes avoid backslashes
-- (standard_conforming_strings) like the earlier migrations.
--
-- CreateEnum
CREATE TYPE "CompanyKind" AS ENUM ('ORGANIZER', 'SPONSOR', 'PARTNER', 'OTHER');

-- CreateTable
CREATE TABLE "companies" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "slug" VARCHAR(60) NOT NULL,
    "display_name" VARCHAR(120) NOT NULL,
    "country" VARCHAR(2) NOT NULL,
    "kind" "CompanyKind" NOT NULL,
    "description" VARCHAR(2000),
    "website_url" VARCHAR(300),
    "legal_name" VARCHAR(200) NOT NULL,
    "trade_registry_number" VARCHAR(20),
    "mersis_number" VARCHAR(16),
    "tax_number" VARCHAR(20),
    "tax_office" VARCHAR(120),
    "chamber_name" VARCHAR(200),
    "chamber_registered_at" DATE,
    "nace_code" VARCHAR(8),
    "address" VARCHAR(500),
    "contact_email" VARCHAR(254),
    "created_by_id" UUID NOT NULL,
    "updated_by_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,
    "deleted_at" TIMESTAMPTZ(6),

    CONSTRAINT "companies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "companies_slug_key" ON "companies"("slug");

-- CreateIndex
CREATE INDEX "companies_created_at_id_idx" ON "companies"("created_at" DESC, "id" DESC);

-- Format rules: the last line of defence behind the DTO.
ALTER TABLE "companies"
    ADD CONSTRAINT "companies_slug_format_check" CHECK ("slug" ~ '^[a-z0-9-]{3,60}$'),
    ADD CONSTRAINT "companies_country_format_check" CHECK ("country" ~ '^[A-Z]{2}$'),
    ADD CONSTRAINT "companies_website_url_https_check" CHECK ("website_url" IS NULL OR "website_url" ~ '^https://'),
    ADD CONSTRAINT "companies_mersis_number_format_check" CHECK ("mersis_number" IS NULL OR "mersis_number" ~ '^[0-9]{16}$'),
    ADD CONSTRAINT "companies_nace_code_format_check" CHECK ("nace_code" IS NULL OR "nace_code" ~ '^[0-9]{2}[.][0-9]{2}[.][0-9]{2}$');

-- A slug is the company's public identity and a deleted row must stay deleted:
-- neither may be rewritten, even by a future caller that bypasses the service.
CREATE OR REPLACE FUNCTION public.kfa_company_identity_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW."slug" IS DISTINCT FROM OLD."slug" THEN
        RAISE EXCEPTION 'company slug is immutable after insert'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Create a new company instead of renaming the slug.';
    END IF;

    IF OLD."deleted_at" IS NOT NULL AND NEW."deleted_at" IS NULL THEN
        RAISE EXCEPTION 'a deleted company cannot be restored'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Create a new company instead of resuming a retired slug.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS companies_identity_immutable ON public.companies;
CREATE TRIGGER companies_identity_immutable
BEFORE UPDATE ON public.companies
FOR EACH ROW
EXECUTE FUNCTION public.kfa_company_identity_immutable();

-- The runtime role reads, adds and corrects a company, and never deletes one:
-- a deletion is an UPDATE of `deleted_at`, and the row (with its slug) stays.
-- The default privileges in db/roles.sql would grant DELETE anyway; this
-- explicit block keeps the migration self-contained and is guarded so it also
-- applies where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.companies FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.companies TO kfa_app';
    END IF;
END
$$;
