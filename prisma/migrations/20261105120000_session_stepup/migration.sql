-- Stage 3.2c: freshness of a re-authentication for sensitive actions. A NULL
-- value means the session never stepped up.
ALTER TABLE "sessions" ADD COLUMN "stepup_at" TIMESTAMPTZ(6);
