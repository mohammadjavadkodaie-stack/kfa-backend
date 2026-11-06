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
  for (const limit of DOCUMENT_VIEW_LINK_LIMITS) {
    const decision = await rateLimit.consume({
      scope: DOCUMENT_VIEW_LINK_RATE_LIMIT_SCOPE,
      identifier: userId,
      ...limit,
    });

    if (!decision.allowed) {
      return writeTooManyRequests(response, request, decision.retryAfterSeconds);
    }
  }

  return null;
}
