-- Stage 3.4b: the database itself guarantees at most one OWNER row.
--
-- Why: the trigger in 20261103120000_owner_protection_trigger only fences off
-- kfa_app. A partial unique index is visible to every role, so it also holds
-- for the deliberate break-glass path (kfa_migrator, superuser) and for any
-- manual operator repair. The indexed expression is a constant, and the
-- predicate excludes every row that is not an owner, so normal accounts stay
-- unconstrained while a second OWNER becomes a unique violation (23505).
--
-- Safe on a database with zero or one owner. With more than one, the migration
-- refuses to apply instead of deleting rows; only the count is reported, never
-- names, ids or phone numbers.
DO $$
DECLARE
    owner_count integer;
BEGIN
    SELECT count(*)::integer
    INTO owner_count
    FROM public.users
    WHERE "role" = 'OWNER';

    IF owner_count > 1 THEN
        RAISE EXCEPTION 'cannot enforce a single owner: % owner rows exist', owner_count
            USING ERRCODE = 'unique_violation';
    END IF;
END
$$;

CREATE UNIQUE INDEX "users_single_owner_key"
    ON public.users ((true))
    WHERE "role" = 'OWNER';
