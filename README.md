# KFA backend

NestJS (Express) API skeleton with a default-deny security baseline. No DB/cache/ORM yet.

## Run

1. `pnpm install`
2. `cp .env.example .env` and fill it in (never commit `.env`).
3. `pnpm start:dev` (dev) or `pnpm build && pnpm start:prod`.

## Verify

`pnpm format` · `pnpm typecheck` · `pnpm test` (unit) · `pnpm test:e2e` (API, rate limit, boot guards).

## Security rules

- Env is zod-validated at boot; only variable names are reported, never values.
- Auth is default-deny: only `@Public()` routes are reachable (today `GET /health`).
- Explicit CORS allowlist, helmet, body limits, request ids; errors expose `{statusCode, message, requestId}` only.
- Logs redact credentials and bodies, and strip query strings.
- Rate limiting is in-memory: production boot is refused until a Redis store is wired.
