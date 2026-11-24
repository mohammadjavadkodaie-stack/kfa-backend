/**
 * The budget every staff ranking write shares.
 *
 * Per user, never per address: a staff desk may share one network, and a refusal
 * there would be a denial of service between real reviewers. The same scope
 * covers create, update and delete on purpose, so deleting and re-entering a
 * result cannot buy a fresh allowance. Read routes are not charged - the global
 * throttle already covers them.
 */

export const RANKING_WRITE_RATE_LIMIT_SCOPE = 'staff-ranking-write';

export const RANKING_WRITE_LIMITS = [
  { limit: 30, windowSeconds: 60 },
  { limit: 300, windowSeconds: 3_600 },
] as const;

/**
 * The budget of the public leaderboard, per address because the caller has no
 * session at all. A separate scope from the single-athlete read, so exhausting
 * one paging loop does not close the other surface.
 *
 * Paging is cheap (one indexed read), so the minute window is generous enough
 * for a front end to walk several pages, while the hourly cap still stops a
 * script that tries to enumerate the whole table through short pages.
 */
export const PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE = 'public-ranking-list';

export const PUBLIC_RANKING_LIST_LIMITS = [
  { limit: 60, windowSeconds: 60 },
  { limit: 600, windowSeconds: 3_600 },
] as const;

/** The single-athlete read gets its own, slightly wider, per-address budget. */
export const PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE = 'public-ranking-read';

export const PUBLIC_RANKING_READ_LIMITS = [
  { limit: 120, windowSeconds: 60 },
  { limit: 1_200, windowSeconds: 3_600 },
] as const;
