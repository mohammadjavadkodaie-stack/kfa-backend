-- One priced offer per competition period. The price is money, so it is stored
-- as a decimal, seeded once, and never deleted: a past payment keeps its own
-- expected amount either way, but the history of the offer stays readable.
CREATE TABLE "billing_plans" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "code" TEXT NOT NULL,
    "period_key" TEXT NOT NULL,
    "price_usd" DECIMAL(18,6) NOT NULL,
    "period_days" INTEGER NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "billing_plans_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "billing_plans_price_usd_check" CHECK ("price_usd" > 0),
    CONSTRAINT "billing_plans_period_days_check" CHECK ("period_days" > 0)
);

CREATE UNIQUE INDEX "billing_plans_code_key" ON "billing_plans"("code");

-- The owner's opening price: 4.20 USD for a one-year period. Re-runnable, and
-- it never overwrites a price that was already changed.
INSERT INTO "billing_plans" ("code", "period_key", "price_usd", "period_days", "updated_at")
VALUES ('standard', 'default', 4.200000, 365, CURRENT_TIMESTAMP)
ON CONFLICT ("code") DO NOTHING;

CREATE TRIGGER "billing_plans_no_delete"
BEFORE DELETE ON "billing_plans"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_billing_reject_delete();

REVOKE ALL ON TABLE public.billing_plans FROM PUBLIC;

-- Default privileges in db/roles.sql grant DELETE on new tables, so it is
-- revoked here. Guarded for environments where the runtime role arrives later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.billing_plans FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.billing_plans TO kfa_app';
    END IF;
END
$$;