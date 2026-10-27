/**
 * Security-relevant constants that must not drift between environments.
 */

/** Rate-limit window in milliseconds. */
export const RATE_LIMIT_DEFAULT_TTL_MS = 60_000;

/** Requests allowed per window and client (in-memory store, single instance). */
export const RATE_LIMIT_DEFAULT_LIMIT = 100;
