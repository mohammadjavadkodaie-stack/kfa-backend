-- KFA least-privilege database roles (stage 1).
--
-- NOT executed by the application. Run once as a superuser (or a role with
-- CREATEROLE + schema ownership), connected to the target database:
--
--   psql -d kfa -U postgres -f db/roles.sql
--
-- Replace every <SET-STRONG-PASSWORD> placeholder before running, or prefer
-- psql's `\password kfa_app` / `\password kfa_migrator` so the secret never
-- lands in shell history or in this file. Never commit real credentials.
--
-- Roles:
--   kfa_migrator - owns schema objects, runs DDL/migrations only.
--   kfa_app      - runtime role: no DDL, no ownership, SELECT/INSERT-only on
--                  audit_log, normal CRUD on future application tables.
--
-- This file is idempotent except for the two CREATE ROLE statements: if the
-- roles already exist, skip/replace them with ALTER ROLE ... PASSWORD.

CREATE ROLE kfa_migrator WITH LOGIN PASSWORD '<SET-STRONG-PASSWORD>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

CREATE ROLE kfa_app WITH LOGIN PASSWORD '<SET-STRONG-PASSWORD>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

-- Database-level lockdown: PUBLIC loses CONNECT/TEMP, only the two roles stay.
DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM kfa_app, kfa_migrator', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO kfa_app, kfa_migrator', current_database());
END
$$;

-- Schema ownership: only the migration role may create/alter/drop objects.
ALTER SCHEMA public OWNER TO kfa_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO kfa_app;

-- audit_log remains the only append-only table.
-- Future tables/sequences created by kfa_migrator: normal CRUD for the app.
ALTER DEFAULT PRIVILEGES FOR ROLE kfa_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kfa_app;
ALTER DEFAULT PRIVILEGES FOR ROLE kfa_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO kfa_app;

-- Tables that already exist must not be reachable through PUBLIC.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

-- audit_log is the exception to the default privileges: SELECT + INSERT only.
-- (The migration also applies this, so either execution order is safe.)
DO $$
BEGIN
    IF to_regclass('public.audit_log') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.audit_log FROM PUBLIC, kfa_app';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.audit_log TO kfa_app';
    END IF;
END
$$;

-- notifications: the runtime role reads its own rows and appends new ones, and
-- may only ever stamp read_at. No DELETE - a notification is not a
-- client-managed row; a purge path, if wanted, is a later feature. The
-- migration applies the same grants (guarded on the role existing), so either
-- execution order is safe.
DO $$
BEGIN
    IF to_regclass('public.notifications') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.notifications FROM PUBLIC, kfa_app';
        EXECUTE 'GRANT SELECT, INSERT ON TABLE public.notifications TO kfa_app';
        EXECUTE 'GRANT UPDATE ("read_at") ON TABLE public.notifications TO kfa_app';
    END IF;
END
$$;

-- profile_photos: the runtime role reads, inserts and stamps a review decision,
-- but never deletes a photo. The migration applies the same grants.
DO $$
BEGIN
    IF to_regclass('public.profile_photos') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.profile_photos FROM PUBLIC, kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.profile_photos TO kfa_app';
    END IF;
END
$$;

-- Billing tables: read and write, never DELETE. Payment terms are frozen by a
-- trigger in the billing migration. The migration applies the same grants.
DO $$
BEGIN
    IF to_regclass('public.subscriptions') IS NOT NULL THEN
        EXECUTE 'REVOKE ALL ON TABLE public.subscriptions, public.payments, public.webhook_events, public.billing_plans FROM PUBLIC, kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON TABLE public.subscriptions, public.payments, public.webhook_events, public.billing_plans TO kfa_app';
    END IF;
END
$$;
