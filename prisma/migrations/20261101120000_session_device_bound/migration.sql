-- Stage 2.3b: a refresh without X-Device-Key must be refused for a session that
-- was created with one. Existing rows default to bound (fail closed).
ALTER TABLE "sessions" ADD COLUMN "device_bound" BOOLEAN NOT NULL DEFAULT true;
