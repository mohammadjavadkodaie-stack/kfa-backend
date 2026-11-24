-- Stage 7c: following an athlete and liking an approved photo.
--
-- Two small side tables, both shaped as a unique pair so a repeated request is a
-- no-op at the database and not only in the service:
--
-- 1. `athlete_follows` - one row per (follower, followed profile). Both sides
--    cascade: an account or a profile that goes away takes its follow rows with
--    it. The extra index serves the only aggregate read, counting followers.
-- 2. `photo_likes` - one row per (photo, user), same reasoning. The extra index
--    serves the like count of one photo.
--
-- Generated with `prisma migrate diff` (no database was contacted); the grants
-- below are appended by hand so the runtime role can insert and withdraw these
-- two rows and nothing more.

-- CreateTable
CREATE TABLE "athlete_follows" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "follower_user_id" UUID NOT NULL,
    "followed_profile_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "athlete_follows_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "photo_likes" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "photo_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "photo_likes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "athlete_follows_followed_profile_id_idx" ON "athlete_follows"("followed_profile_id");

-- CreateIndex
CREATE UNIQUE INDEX "athlete_follows_follower_user_id_followed_profile_id_key" ON "athlete_follows"("follower_user_id", "followed_profile_id");

-- CreateIndex
CREATE INDEX "photo_likes_photo_id_idx" ON "photo_likes"("photo_id");

-- CreateIndex
CREATE UNIQUE INDEX "photo_likes_photo_id_user_id_key" ON "photo_likes"("photo_id", "user_id");

-- AddForeignKey
ALTER TABLE "athlete_follows" ADD CONSTRAINT "athlete_follows_follower_user_id_fkey" FOREIGN KEY ("follower_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "athlete_follows" ADD CONSTRAINT "athlete_follows_followed_profile_id_fkey" FOREIGN KEY ("followed_profile_id") REFERENCES "athlete_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "photo_likes" ADD CONSTRAINT "photo_likes_photo_id_fkey" FOREIGN KEY ("photo_id") REFERENCES "profile_photos"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "photo_likes" ADD CONSTRAINT "photo_likes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- The runtime role may add and withdraw these two rows and nothing else: no
-- UPDATE (a follow or a like is never edited, only created or deleted) and no
-- privilege on any other table. The default privileges in db/roles.sql grant
-- UPDATE too, so the REVOKE comes first. Guarded so the migration also applies
-- where the runtime role is created later.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'kfa_app') THEN
        EXECUTE 'REVOKE ALL ON TABLE public.athlete_follows, public.photo_likes FROM kfa_app';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON TABLE public.athlete_follows, public.photo_likes TO kfa_app';
    END IF;
END
$$;
