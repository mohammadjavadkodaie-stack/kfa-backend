-- Additive migration generated with prisma migrate diff (no database connection).
ALTER TABLE "users" ADD COLUMN "is_approver" BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE "pending_approvals" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "action_type" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "requested_by" UUID NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "executed_at" TIMESTAMPTZ(6),
    "approved_by" UUID,
    "approved_at" TIMESTAMPTZ(6),
    CONSTRAINT "pending_approvals_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "pending_approvals_status_expires_at_idx"
    ON "pending_approvals"("status", "expires_at");
