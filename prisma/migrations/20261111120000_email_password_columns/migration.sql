-- E2-a: email and password identity columns.
--
-- Additive only. The phone column, its unique index and its CHECK stay exactly
-- as they are, so SMS-OTP login keeps working; the only change to phone is that
-- it may now be NULL for an account that identifies itself by email instead.
--
-- The application only ever writes `email` in its normalized form (lowercase,
-- ASCII or punycode domain), which is what the format CHECK enforces. NULL is
-- always allowed: an existing phone-only account has no email yet.

ALTER TABLE "users"
    ADD COLUMN "email" TEXT,
    ADD COLUMN "password_hash" TEXT,
    ADD COLUMN "email_verified_at" TIMESTAMPTZ(6);

-- A phone-less account is now legal. The existing unique index still rejects a
-- duplicate number and PostgreSQL treats every NULL as distinct.
ALTER TABLE "users" ALTER COLUMN "phone" DROP NOT NULL;

-- Same name Prisma derives from `@unique`, so a later `migrate diff` stays clean.
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- Every constraint is NULL-tolerant: only a stored value is validated.
ALTER TABLE "users"
    ADD CONSTRAINT "users_email_format_check" CHECK ("email" IS NULL OR "email" ~ '^[a-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}[.])+[a-z]{2,63}$'),
    ADD CONSTRAINT "users_email_length_check" CHECK ("email" IS NULL OR char_length("email") <= 254),
    ADD CONSTRAINT "users_password_hash_length_check" CHECK ("password_hash" IS NULL OR char_length("password_hash") BETWEEN 20 AND 512);
