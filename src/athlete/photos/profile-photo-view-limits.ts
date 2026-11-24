/**
 * The budget both preview-link routes share (owner and staff).
 *
 * Kept in one place so the two routes cannot drift apart: a second route with a
 * laxer limit would be the cheapest way around this one. Counted per user id -
 * issuing a link is the only way to reach a non-public photo.
 */
export const PROFILE_PHOTO_VIEW_LINK_RATE_LIMIT_SCOPE = 'profile-photo-view-link';
export const PROFILE_PHOTO_VIEW_LINK_LIMITS = [
  { limit: 20, windowSeconds: 60 },
  { limit: 100, windowSeconds: 3_600 },
] as const;

/**
 * The budget of the route that serves the bytes behind a preview link.
 *
 * Per address, because the caller may have no session at all (the token is the
 * credential). Redemption is single use, so every request in this bucket is a
 * real link; the numbers stay tight for that reason.
 */
export const PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE = 'profile-photo-view-file';
export const PROFILE_PHOTO_VIEW_FILE_LIMITS = [
  { limit: 20, windowSeconds: 60 },
  { limit: 100, windowSeconds: 3_600 },
] as const;

/**
 * Per-address budgets for the public, unauthenticated profile-photo routes.
 *
 * These endpoints hand out bytes with no login at all, so the bucket is the
 * client address. Like every limiter here the scopes are unique per surface:
 * exhausting one must not slow the others down.
 */

export const PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE = 'profile-photo-public-file';
export const PROFILE_PHOTO_PUBLIC_FILE_LIMITS = [
  { limit: 120, windowSeconds: 60 },
  { limit: 1_200, windowSeconds: 3_600 },
] as const;

export const PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE = 'profile-photo-public-list';
export const PROFILE_PHOTO_PUBLIC_LIST_LIMITS = [
  { limit: 60, windowSeconds: 60 },
  { limit: 600, windowSeconds: 3_600 },
] as const;
