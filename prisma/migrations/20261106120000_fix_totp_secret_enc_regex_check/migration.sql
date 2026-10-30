-- PostgreSQL caps regex repetition counts at 255, so the original
-- "^v1[...]{8,8000}$" rule made every write to this table fail with SQLSTATE
-- 2201B. The charset rule now carries no counted repetition and the payload
-- bound ("v1" tag plus 8..8000 characters, i.e. 10..8002 in total) is enforced
-- with length(), so the accepted set of values is unchanged.
-- A CHECK swap leaves the table ACLs (the kfa_app grants from the default
-- privileges) untouched, hence no GRANT/REVOKE here.

ALTER TABLE "totp_credentials"
    DROP CONSTRAINT IF EXISTS "totp_credentials_secret_enc_format_check";

ALTER TABLE "totp_credentials"
    ADD CONSTRAINT "totp_credentials_secret_enc_format_check" CHECK (
        "secret_enc" ~ '^v1[A-Za-z0-9+/=:._-]+$'
        AND length("secret_enc") BETWEEN 10 AND 8002
    );
