/**
 * The budgets of the two public company reads.
 *
 * Per address, because the caller has no session at all. A separate scope from
 * the single read, so exhausting one paging loop does not close the other
 * surface, and a separate pair from every staff route.
 *
 * Paging is cheap (one indexed read), so the minute window is generous enough
 * for a front end to walk several pages, while the hourly cap still stops a
 * script that tries to enumerate the whole table through short pages.
 */
export const PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE = 'public-company-list';

export const PUBLIC_COMPANY_LIST_LIMITS = [
  { limit: 60, windowSeconds: 60 },
  { limit: 600, windowSeconds: 3_600 },
] as const;

/** The single-company read gets its own, slightly wider, per-address budget. */
export const PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE = 'public-company-read';

export const PUBLIC_COMPANY_READ_LIMITS = [
  { limit: 120, windowSeconds: 60 },
  { limit: 1_200, windowSeconds: 3_600 },
] as const;
