import type { Response } from 'express';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import { writeTooManyRequests, type ErrorResponseBody } from '../../common/errors/error-response';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';

/**
 * The budget both view-link routes share.
 *
 * Kept in one place so the owner route and the staff route cannot drift apart: a
 * second route with a laxer limit would be the cheapest way around this one.
 */
export const DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE = 'document-view-link';

/**
 * Per-user limits, checked before the service runs.
 *
 * Issuing a link is one indexed read, one audit row and one nonce: cheap, but it
 * is also the only way to reach a document, so the burst window keeps a script
 * from probing ids quickly and the hourly budget caps a long attempt. Both are
 * per user - never per address, which a shared network would turn into a denial
 * of service between real users.
 */
export const DOCUMENT_VIEW_LINK_LIMITS = [
  { limit: 10, windowSeconds: 60 },
  { limit: 30, windowSeconds: 3_600 },
] as const;

/**
 * Consumes both windows and reports the refusal, if any.
 *
 * The answer goes through the shared helper, so the envelope and the
 * `Retry-After` rounding match every other limited route in the API.
 */
export async function refuseViewLinkWhenOverLimit(
  rateLimit: RateLimitService,
  userId: string,
  request: AuthenticatedRequest,
  response: Response,
): Promise<ErrorResponseBody | null> {
  return consumeOrRefuse(
    rateLimit,
    DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
    DOCUMENT_VIEW_LINK_LIMITS,
    userId,
    request,
    response,
  );
}

/**
 * The budget of the route that serves the bytes: `GET /documents/view/:token`.
 *
 * A separate scope from the issuing one, and per address rather than per user:
 * the caller of that route may have no session at all (the token is the
 * credential), so there is no user id to count against. Twenty a minute is more
 * than a page of thumbnails needs and far less than an id-guessing script, and
 * the hourly budget caps a long attempt. Redemption is single use, so every one
 * of those twenty is a real link - a refused attempt costs a nonce, which is
 * why the numbers are this tight.
 */
export const DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE = 'document-view-file';

/** Per-address limits for the bytes route, checked before `redeem()` runs. */
export const DOCUMENT_VIEW_FILE_LIMITS = [
  { limit: 20, windowSeconds: 60 },
  { limit: 100, windowSeconds: 3_600 },
] as const;

/**
 * Consumes both windows for one address and reports the refusal, if any.
 *
 * Failed attempts count too: the counters are spent before the token is even
 * looked at, so a caller cannot buy extra guesses with malformed links.
 */
export async function refuseViewFileWhenOverLimit(
  rateLimit: RateLimitService,
  address: string,
  request: RequestIdSource,
  response: Response,
): Promise<ErrorResponseBody | null> {
  return consumeOrRefuse(
    rateLimit,
    DOCUMENT_VIEW_FILE_RATE_LIMIT_SCOPE,
    DOCUMENT_VIEW_FILE_LIMITS,
    address,
    request,
    response,
  );
}

/** The one fact a refusal needs from the request: the id the envelope echoes. */
interface RequestIdSource {
  readonly id?: unknown;
}

/**
 * The shared loop: the windows are checked in order and the first refusal wins,
 * so a caller that is out of budget never reaches the service or the second
 * counter.
 */
async function consumeOrRefuse(
  rateLimit: RateLimitService,
  scope: string,
  limits: readonly { readonly limit: number; readonly windowSeconds: number }[],
  identifier: string,
  request: RequestIdSource,
  response: Response,
): Promise<ErrorResponseBody | null> {
  for (const limit of limits) {
    const decision = await rateLimit.consume({ scope, identifier, ...limit });

    if (!decision.allowed) {
      return writeTooManyRequests(response, request, decision.retryAfterSeconds);
    }
  }

  return null;
}
