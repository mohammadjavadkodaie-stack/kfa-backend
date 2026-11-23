-- Billing schema (stage 1.1). Hand-written for the triggers and the privilege
-- split, which Prisma cannot express. Apply as kfa_migrator.

CREATE TYPE "SubscriptionStatus" AS ENUM ('NONE', 'PENDING', 'ACTIVE', 'EXPIRED', 'REFUNDED');
CREATE TYPE "PaymentProvider" AS ENUM ('NOWPAYMENTS', 'PAYPAL');
CREATE TYPE "PaymentStatus" AS ENUM ('CREATED', 'PENDING', 'CONFIRMED', 'FAILED', 'REFUNDED', 'CHARGEBACK');

CREATE TABLE "subscriptions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "period_key" TEXT NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'NONE',
    "starts_at" TIMESTAMPTZ(6),
    "expires_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "subscriptions_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "subscriptions_user_id_period_key_key" ON "subscriptions"("user_id", "period_key");
CREATE INDEX "subscriptions_user_id_idx" ON "subscriptions"("user_id");

CREATE TABLE "payments" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "subscription_id" UUID NOT NULL,
    "provider" "PaymentProvider" NOT NULL,
    "provider_payment_id" TEXT NOT NULL,
    "expected_amount" DECIMAL(18,6) NOT NULL,
    "expected_currency" TEXT NOT NULL,
    "expected_network" TEXT,
    "paid_amount" DECIMAL(18,6),
    "status" "PaymentStatus" NOT NULL DEFAULT 'CREATED',
    "confirmed_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "payments_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "payments_provider_provider_payment_id_key" ON "payments"("provider", "provider_payment_id");
CREATE INDEX "payments_subscription_id_idx" ON "payments"("subscription_id");

CREATE TABLE "webhook_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider" "PaymentProvider" NOT NULL,
    "event_id" TEXT NOT NULL,
    "payload_hash" TEXT NOT NULL,
    "signature_valid" BOOLEAN NOT NULL,
    "received_at" TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
    "processed_at" TIMESTAMPTZ(6),
    "outcome" TEXT,

    CONSTRAINT "webhook_events_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "webhook_events_provider_event_id_key" ON "webhook_events"("provider", "event_id");

ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- History is kept: a subscription with payments cannot be removed, and the
-- delete trigger below refuses payment deletion outright.
ALTER TABLE "payments" ADD CONSTRAINT "payments_subscription_id_fkey"
    FOREIGN KEY ("subscription_id") REFERENCES "subscriptions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- The agreed amount, currency, network and provider identifiers are fixed once
-- the row exists; confirmation may only set paid_amount/status/confirmed_at.
CREATE OR REPLACE FUNCTION public.kfa_payment_terms_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW."expected_amount" IS DISTINCT FROM OLD."expected_amount"
        OR NEW."expected_currency" IS DISTINCT FROM OLD."expected_currency"
        OR NEW."expected_network" IS DISTINCT FROM OLD."expected_network"
        OR NEW."provider" IS DISTINCT FROM OLD."provider"
        OR NEW."provider_payment_id" IS DISTINCT FROM OLD."provider_payment_id"
    THEN
        RAISE EXCEPTION 'payment terms are immutable after insert'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Insert a new payment row instead of rewriting the agreed terms.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER "payments_terms_immutable"
BEFORE UPDATE ON "payments"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_payment_terms_immutable();

CREATE OR REPLACE FUNCTION public.kfa_billing_reject_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% rows cannot be deleted', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Keep the financial and webhook history.';
END;
$$;

CREATE TRIGGER "payments_no_delete"
BEFORE DELETE ON "payments"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_billing_reject_delete();

CREATE TRIGGER "webhook_events_no_delete"
BEFORE DELETE ON "webhook_events"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_billing_reject_delete();

REVOKE ALL ON TABLE public.subscriptions, public.payments, public.webhook_events FROM PUBLIC;

-- Default privileges in db/roles.sql grant DELETE on new tables, so it is
-- revoked here. Guarded for environments where the runtime role arrives later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.subscriptions, public.payments, public.webhook_events FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.subscriptions, public.payments, public.webhook_events TO kfa_app';
    END IF;
END
$$;
