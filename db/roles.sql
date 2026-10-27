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
