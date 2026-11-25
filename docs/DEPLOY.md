# KFA production deployment

This guide targets an Ubuntu 24.04 VPS with Docker Compose and Caddy. Run commands from the backend repository unless stated otherwise.

## Before you start

- Point DNS A and AAAA records for the apex domain (and optional `www`) to the VPS.
- Allow only SSH, HTTP, and HTTPS: `sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw allow 443/udp && sudo ufw enable`.
- Use SSH keys only; disable password SSH login after confirming key access.
- Install Docker Engine and the Compose plugin from Docker's official Ubuntu instructions, then add the operator to the `docker` group and re-login.

Clone both repositories side by side, for example `~/KFA/KFA-backend` and `~/KFA/KFA-frontend`. The default frontend build context is `../../KFA-frontend`; override `FRONTEND_CONTEXT` if your layout differs.

## Configure and boot

```sh
cd ~/KFA/KFA-backend
cp deploy/.env.production.example deploy/.env.production
chmod 600 deploy/.env.production
# Edit every placeholder; do not commit deploy/.env.production.

docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml up -d postgres redis clamav
# Wait until those three services report healthy.
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml --profile tools run --rm migrate
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml up -d
```

The migration command is deliberately a one-off and is not run on app startup. Caddy is the only service publishing ports. The backend is reachable only on Docker networks.

## Verify and first owner

Check `https://$SITE_DOMAIN/health`, then load the site, complete sign-up with a real email, and confirm Turnstile succeeds.

The identity flow is email only: `/auth/otp/*`, `/auth/register`, `/auth/login` and `/auth/phone-change/*` no longer exist and answer the same generic 404 as any unknown route, and no SMS provider is configured. Sign-up, login, password reset and email change run through the email flow.

### Bootstrap the first OWNER

The first staff account signs up like any other user through the email flow. Promote it exactly once, from the host, after the stack is healthy:

```sh
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml exec backend node dist/scripts/bootstrap-owner.js --email ops@example.com --confirm
```

What the command guarantees:

- Without `--confirm` it prints usage and exits 2 without touching the database.
- The account must already exist; unknown or unusable addresses are refused generically (exit 1) and nothing is written.
- It refuses with a non-zero exit when any OWNER already exists, so it is safe to re-run after a failed attempt.
- The role change goes through the application's compare-and-set repository path (no raw SQL) and appends one audit row: action `owner.bootstrapped`, actor `system:bootstrap-cli`, masked email, previous and new role.
- The database trigger only lets a role other than the runtime role create the OWNER, so the command connects with `MIGRATION_DATABASE_URL`, which the backend container already receives. Without that URL it falls back to the runtime URL and fails closed.
- The promoted account still enrolls its own TOTP second factor at first staff sign-in; the CLI never bypasses the staff gate.

## Updates and rollback

```sh
git pull --ff-only
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml build
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml --profile tools run --rm migrate
docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml up -d
```

For rollback, check out the previously deployed commit, rebuild, run only migrations compatible with that version, and bring the stack up. Do not roll back across irreversible migrations without a tested database restore plan.

View logs with `docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml logs -f --tail=200 backend caddy`. Run `deploy/backup.sh` from the repository; example cron (daily at 02:15 UTC):

```cron
15 2 * * * cd /home/ubuntu/KFA/KFA-backend && BACKUP_DIR=/var/backups/kfa KEEP=14 ./deploy/backup.sh >>/var/log/kfa-backup.log 2>&1
```

The backup script covers PostgreSQL only. Documents are encrypted in the private S3-compatible bucket and require provider-side versioning/backup.

### Nightly encrypted backup with integrity check and email delivery

`deploy/backup.sh` keeps one compressed dump on the host. `scripts/run-backup.js` is the copy that leaves the host: it dumps the database in custom format with `pg_dump`, encrypts the dump with `BACKUP_ENCRYPTION_KEY` (AES-256-GCM, random IV), decrypts it again to prove that the file on disk is a real archive, and mails the encrypted file to both owner mailboxes. Working files live in the container's `/tmp` and are deleted only after at least one delivery succeeded; a failed run keeps them and sends a plain alert instead.

```cron
0 0 * * * cd /home/ubuntu/KFA/KFA-backend && docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml exec -T backend node dist/scripts/run-backup.js >>/var/log/kfa-backup-encrypted.log 2>&1
```

00:00 UTC, deliberately separate from the 02:15 UTC `deploy/backup.sh` job above, so the two never compete for the database.

- Three production variables are required: `BACKUP_ENCRYPTION_KEY` (base64url of exactly 32 bytes, unique from the other secrets), `BACKUP_NOTIFY_EMAIL` and `BACKUP_NOTIFY_EMAIL_EMERGENCY`. Both addresses receive the same attachment, so one failing delivery cannot lose the backup; the API refuses to boot in production when any of the three is missing.
- The exit code is `0` only when the dump was verified and at least one mail was accepted. Any failure exits `1`, logs one structured line, and emails a `backup_failed` alert without an attachment; a run that cannot encrypt or deliver writes no dump at all.
- Restore: decrypt the attachment with `BACKUP_ENCRYPTION_KEY`, then `pg_restore` the result into an empty database.
- The provider rejects oversized attachments (Resend caps a message at roughly 40 MB, and base64 adds a third), so alert on a dump that approaches that size.

## Pre-launch checklist

- [ ] Every secret is unique, generated securely, rotated from placeholders, and stored with mode 600.
- [ ] `EMAIL_FROM` domain is verified in Resend, with SPF and DKIM configured.
- [ ] Turnstile hostname is the real apex hostname.
- [ ] `TRUSTED_PROXY_COUNT=1` matches the actual single Caddy proxy.
- [ ] ClamAV is healthy and signatures have updated successfully.
- [ ] S3 bucket is private and encryption/versioning/least-privilege credentials are enabled.
- [ ] No fake/development provider remains enabled (email, captcha), and the removed phone/OTP routes answer a generic 404.
- [ ] The first OWNER is bootstrapped once with `bootstrap-owner.js --confirm`, and its TOTP second factor is enrolled.
- [ ] Backups and a restore have been tested.
- [ ] Owner/admin is informed of rate-limit and captcha behavior.

UNSURE items: Alpine is selected because Prisma 6 supports the musl runtime used by `node:24-alpine`; validate against the generated Prisma engine in CI. The frontend context defaults to the sibling `../../KFA-frontend` path; its environment contract is runtime `APP_URL`, `SESSION_SECRET`, `LOG_LEVEL`, `CAPTCHA_PROVIDER`, `TURNSTILE_SITE_KEY`, `NODE_ENV` and `TRUSTED_PROXY_COUNT` (pinned to 1 in the compose file), plus the `BACKEND_INTERNAL_URL` build argument defaulting to `http://backend:3001`. S3 provider is intentionally generic because `env.ts` defines an S3-compatible interface.
