# KFA backend

NestJS (Express) API skeleton with a default-deny security baseline, Prisma/PostgreSQL
persistence and an append-only, hash-chained audit log. No cache/Redis yet.

## Run

1. `pnpm install`
2. `cp .env.example .env` and fill it in (never commit `.env`).
3. `pnpm start:dev` (dev) or `pnpm build && pnpm start:prod`.

## Verify

`pnpm format` · `pnpm typecheck` · `pnpm test` (unit) · `pnpm test:e2e` (API, rate limit, boot guards, DB tests when configured).

## Database setup (Postgres + Prisma)

Migrations run as `kfa_migrator`; the API runs as `kfa_app` (no DDL, and `audit_log` is SELECT/INSERT only). Neither role is created automatically.

```powershell
docker compose -f docker-compose.dev.yml up -d   # optional local Postgres, loopback only

# 1. Roles and database, as a superuser (replace the placeholders first)
psql -U postgres -c "CREATE ROLE kfa_migrator LOGIN PASSWORD '<SET-STRONG-PASSWORD>' NOSUPERUSER NOCREATEDB NOCREATEROLE"
psql -U postgres -c "CREATE ROLE kfa_app LOGIN PASSWORD '<SET-STRONG-PASSWORD>' NOSUPERUSER NOCREATEDB NOCREATEROLE"
psql -U postgres -c "CREATE DATABASE kfa OWNER kfa_migrator"

# 2. Least-privilege grants (idempotent)
psql -d kfa -U postgres -f db/roles.sql

# 3. Schema + client, using MIGRATION_DATABASE_URL (.env or the current shell)
pnpm prisma migrate deploy
pnpm prisma generate

# 4. DB integration tests; skipped unless DATABASE_URL_TEST is set (use the kfa_app URL)
$env:DATABASE_URL_TEST = 'postgresql://kfa_app:<SET-STRONG-PASSWORD>@127.0.0.1:5432/kfa?schema=public'
pnpm test:e2e
```

`audit_log` is append-only: `UPDATE`, `DELETE` and `TRUNCATE` are rejected by triggers, and `kfa_app` has no privilege to attempt them anyway.

## Security rules

- Env is zod-validated at boot; only variable names are reported, never values.
- Auth is default-deny: only `@Public()` routes are reachable (today `GET /health`).
- Explicit CORS allowlist, helmet, body limits, request ids; errors expose `{statusCode, message, requestId}` only.
- Logs redact credentials and bodies, and strip query strings.
- Rate limiting is in-memory: production boot is refused until a Redis store is wired.
