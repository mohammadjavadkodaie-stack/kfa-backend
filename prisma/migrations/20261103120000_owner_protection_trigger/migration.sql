-- Stage 3.1c: the runtime role may not create, promote or remove the owner.
--
-- The single owner account is provisioned by the migration role, outside the
-- application. The rule keys on current_user, not on the role the connection
-- logged in as, so a session that switches identity with SET ROLE is fenced in
-- as well.
CREATE OR REPLACE FUNCTION public.kfa_users_protect_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    -- Deliberate break-glass path: kfa_migrator and superusers stay
    -- unrestricted so an operator can create or repair the owner account.
    IF current_user <> 'kfa_app' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        -- No second owner through the application.
        IF NEW."role" = 'OWNER' THEN
            RAISE EXCEPTION 'owner account is protected'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        -- The owner row keeps its identity, role and status; other columns
        -- (phone, username, verification flags) stay editable.
        IF OLD."role" = 'OWNER'
            AND (
                NEW."role" IS DISTINCT FROM OLD."role"
                OR NEW."status" IS DISTINCT FROM OLD."status"
                OR NEW."id" IS DISTINCT FROM OLD."id"
            ) THEN
            RAISE EXCEPTION 'owner account is protected'
                USING ERRCODE = 'insufficient_privilege';
        END IF;

        -- Promotion of any other account is refused as well.
        IF NEW."role" = 'OWNER' AND OLD."role" IS DISTINCT FROM 'OWNER' THEN
            RAISE EXCEPTION 'owner account is protected'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD."role" = 'OWNER' THEN
            RAISE EXCEPTION 'owner account is protected'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- Defense in depth: TRUNCATE bypasses row triggers completely.
CREATE OR REPLACE FUNCTION public.kfa_users_reject_truncate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF current_user = 'kfa_app' THEN
        RAISE EXCEPTION 'users cannot be truncated'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER "users_owner_protected"
BEFORE INSERT OR UPDATE OR DELETE ON "users"
FOR EACH ROW
EXECUTE FUNCTION public.kfa_users_protect_owner();

CREATE TRIGGER "users_no_truncate"
BEFORE TRUNCATE ON "users"
FOR EACH STATEMENT
EXECUTE FUNCTION public.kfa_users_reject_truncate();
