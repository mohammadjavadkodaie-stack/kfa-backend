# KFA backend

NestJS (Express) API skeleton with a default-deny security baseline, Prisma/PostgreSQL
persistence, an append-only, hash-chained audit log and a fail-closed, Redis-backed
rate-limit store.

## Run

1. `pnpm install`
2. `cp .env.example .env` and fill it in (never commit `.env`).
3. `pnpm start:dev` (dev) or `pnpm build && pnpm start:prod`.

## Verify

`pnpm format` · `pnpm typecheck` · `pnpm test` (unit) · `pnpm test:e2e` (API, rate limit, boot guards, DB tests when configured). The real-Redis suite runs only when `REDIS_URL_TEST` is set.

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

## Rate limiting (Redis)

The global `ThrottlerGuard` keeps its counters in Redis whenever `REDIS_URL` is set, and
`RateLimitService` (for explicit checks such as login or OTP) uses the same atomic Lua
script. Identifiers are HMAC-SHA256 hashed with `RATE_LIMIT_HMAC_KEY`, so keys under the
`kfa:rl:` namespace never contain a raw IP, phone number or user id.

```powershell
docker compose -f docker-compose.dev.yml up -d redis   # loopback only, password, no persistence
$env:REDIS_URL = 'redis://:dev-only-change-me@127.0.0.1:6380/0'   # the value in .env.example
$env:REDIS_URL_TEST = $env:REDIS_URL                              # enables the real-Redis e2e suite
pnpm test:e2e
```

Fail-closed behaviour:

- Boot never dials Redis (`lazyConnect`), so an outage appears per request, never as a startup hang.
- Any Redis error, timeout or malformed reply denies the request with a generic `503`; there is no in-memory fallback, so an outage can never turn into an open door.
- `GET /health` skips throttling, so liveness stays green while Redis is down.
- Production requires `rediss://` (TLS) with a password **and** `RATE_LIMIT_HMAC_KEY`; boot is refused otherwise.

## Security rules

- Env is zod-validated at boot; only variable names are reported, never values.
- Auth is default-deny: only `@Public()` routes are reachable (today `GET /health`).
- Explicit CORS allowlist, helmet, body limits, request ids; errors expose `{statusCode, message, requestId}` only.
- Logs redact credentials and bodies, and strip query strings.
- Rate limiting is Redis-backed (atomic fixed window) and fails closed: a missing or unreachable store denies rate-limited requests instead of allowing them.
