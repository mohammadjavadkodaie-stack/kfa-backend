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

Check `https://$SITE_DOMAIN/health`, then load the site, complete sign-up with a real email, and confirm Turnstile succeeds. No first-owner/bootstrap mechanism is documented in this codebase. **UNSURE: bootstrap of the first OWNER is not documented.** Do not improvise a direct database update in production; establish a reviewed, audited bootstrap procedure first.

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

## Pre-launch checklist

- [ ] Every secret is unique, generated securely, rotated from placeholders, and stored with mode 600.
- [ ] `EMAIL_FROM` domain is verified in Resend, with SPF and DKIM configured.
- [ ] Turnstile hostname is the real apex hostname.
- [ ] `TRUSTED_PROXY_COUNT=1` matches the actual single Caddy proxy.
- [ ] ClamAV is healthy and signatures have updated successfully.
- [ ] S3 bucket is private and encryption/versioning/least-privilege credentials are enabled.
- [ ] No fake/development provider remains enabled (`OTP_PROVIDER`, email, captcha).
- [ ] Backups and a restore have been tested.
- [ ] Owner/admin is informed of rate-limit and captcha behavior.

UNSURE items: Alpine is selected because Prisma 6 supports the musl runtime used by `node:24-alpine`; validate against the generated Prisma engine in CI. The frontend context defaults to the sibling `../../KFA-frontend` path and its public URL variable is assumed to be `FRONTEND_PUBLIC_URL` because the frontend repository was not read. S3 provider is intentionally generic because `env.ts` defines an S3-compatible interface. First-owner bootstrap is not documented.
