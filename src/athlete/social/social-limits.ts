/**
 * Anti-bot budgets for following and liking.
 *
 * Every write is counted twice - once per signed-in user and once per client
 * address - and every counter has a minute, an hour and a day window. The tight
 * minute window stops a script, the day window caps a slow one.
 *
 * Follow and unfollow (like and unlike) share one scope on purpose: toggling a
 * button must spend the same budget as the action itself, so "unfollow then
 * follow again" cannot buy a fresh allowance. The scopes are unique per surface
 * and per tracker kind, so a spent like budget never slows a follow down and a
 * shared address cannot silently spend another user's bucket.
 */

/** One fixed window: at most `limit` hits per `windowSeconds`. */
export interface RateWindow {
  readonly limit: number;
  readonly windowSeconds: number;
}

export const FOLLOW_RATE_LIMIT_SCOPES = {
  user: 'athlete-follow-user',
  address: 'athlete-follow-ip',
} as const;

export const FOLLOW_LIMITS = {
  user: [
    { limit: 10, windowSeconds: 60 },
    { limit: 40, windowSeconds: 3_600 },
    { limit: 100, windowSeconds: 86_400 },
  ],
  address: [
    { limit: 20, windowSeconds: 60 },
    { limit: 200, windowSeconds: 3_600 },
    { limit: 400, windowSeconds: 86_400 },
  ],
} as const satisfies Record<keyof typeof FOLLOW_RATE_LIMIT_SCOPES, readonly RateWindow[]>;

export const PHOTO_LIKE_RATE_LIMIT_SCOPES = {
  user: 'photo-like-user',
  address: 'photo-like-ip',
} as const;

export const PHOTO_LIKE_LIMITS = {
  user: [
    { limit: 30, windowSeconds: 60 },
    { limit: 120, windowSeconds: 3_600 },
    { limit: 300, windowSeconds: 86_400 },
  ],
  address: [
    { limit: 60, windowSeconds: 60 },
    { limit: 600, windowSeconds: 3_600 },
    { limit: 1_500, windowSeconds: 86_400 },
  ],
} as const satisfies Record<keyof typeof PHOTO_LIKE_RATE_LIMIT_SCOPES, readonly RateWindow[]>;

/**
 * The public like counter takes no identity at all, so only the address is
 * counted. It is a read, but a script would use it to harvest engagement, and
 * the route stays cheaper than a like write.
 */
export const PHOTO_LIKE_COUNT_RATE_LIMIT_SCOPE = 'photo-like-count-ip';
export const PHOTO_LIKE_COUNT_LIMITS = [
  { limit: 120, windowSeconds: 60 },
  { limit: 1_200, windowSeconds: 3_600 },
  { limit: 5_000, windowSeconds: 86_400 },
] as const satisfies readonly RateWindow[];
