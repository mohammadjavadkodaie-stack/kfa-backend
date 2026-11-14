# PostgreSQL restore

1. Stop the backend and frontend: `docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml stop backend frontend`.
2. Start PostgreSQL if needed: `docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml up -d postgres` and wait for it to be healthy.
3. Decompress the selected backup into PostgreSQL (this replaces data):
   `gzip -dc backups/kfa-YYYYMMDDTHHMMSSZ.sql.gz | docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"`.
4. Run migrations with the tools profile, then start the app: `docker compose --env-file deploy/.env.production -f deploy/docker-compose.prod.yml --profile tools run --rm migrate` and `... up -d`.
5. Verify `/health`, HTTPS, and a sign-in flow.

The script backs up PostgreSQL only. Documents are encrypted in the configured private S3-compatible bucket and must be protected/versioned by that provider separately. Test restores on a non-production host before relying on them.
