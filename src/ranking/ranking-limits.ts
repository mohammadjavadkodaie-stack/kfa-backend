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
