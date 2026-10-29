-- Stage 2.3a: a refresh token needs an explicit revocation marker.
-- Deletion would break the rotation chain, and `used_at` alone cannot tell a
-- token that was spent from a token that was killed together with its session.
ALTER TABLE "refresh_tokens" ADD COLUMN "revoked_at" TIMESTAMPTZ(6);
