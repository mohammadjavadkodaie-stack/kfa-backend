-- Stage 3.1a: the identity verifier is a permission, not a role.
--
-- PostgreSQL cannot drop an enum value, so the role type is rebuilt with the
-- four assignable roles. Accounts that were stored with the old
-- IDENTITY_VERIFIER role keep the permission as a flag and fall back to USER,
-- and every other account keeps its role. New rows default to USER / false.
ALTER TABLE "users" ADD COLUMN "identity_verifier" BOOLEAN NOT NULL DEFAULT false;

UPDATE "users"
SET "identity_verifier" = true, "role" = 'USER'
WHERE "role" = 'IDENTITY_VERIFIER';

ALTER TYPE "Role" RENAME TO "Role_old";
CREATE TYPE "Role" AS ENUM ('USER', 'ATHLETE', 'ADMIN', 'OWNER');

ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT;
ALTER TABLE "users" ALTER COLUMN "role" TYPE "Role" USING ("role"::text::"Role");
ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'USER';

DROP TYPE "Role_old";
