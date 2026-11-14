import type { Response } from 'express';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import type { RateLimitService } from '../rate-limit/rate-limit.service';

/**
 * The counters of the two owner routes.
 *
 * Each route has its own scope, so a spent list budget never closes the delete
 * route (and the other way round), and neither can collide with the upload or
 * view-link counters.
 */
export const DOCUMENT_LIST_RATE_LIMIT_SCOPE = 'document-list';
export const DOCUMENT_DELETE_RATE_LIMIT_SCOPE = 'document-delete';

/**
 * Per-user budget of the list route.
 *
 * Listing is one indexed read of at most a hundred rows and it is what the page
 * asks for on every visit, so the limit is generous: sixty a minute is well
 * above a person clicking around and still bounds a script.
 */
export const DOCUMENT_LIST_LIMITS = [{ limit: 60, windowSeconds: 60 }] as const;

/**
 * Per-user budget of the delete route.
 *
 * Deleting is rare - twenty an hour is more than a person needs and far less
 * than a script that walks ids. Both budgets are per user, never per address:
 * a shared network must not be a denial of service between real users.
 */
export const DOCUMENT_DELETE_LIMITS = [{ limit: 20, windowSeconds: 3_600 }] as const;

/** Consumes the list window and reports the refusal, if any. */
export async function refuseDocumentListWhenOverLimit(
  rateLimit: RateLimitService,
  userId: string,
  request: AuthenticatedRequest,
  response: Response,
): Promise<ErrorResponseBody | null> {
  return consumeOrRefuse(
    rateLimit,
    DOCUMENT_LIST_RATE_LIMIT_SCOPE,
    DOCUMENT_LIST_LIMITS,
    userId,
    request,
    response,
  );
}

/** Consumes the delete window and reports the refusal, if any. */
export async function refuseDocumentDeleteWhenOverLimit(
  rateLimit: RateLimitService,
  userId: string,
  request: AuthenticatedRequest,
  response: Response,
): Promise<ErrorResponseBody | null> {
  return consumeOrRefuse(
    rateLimit,
    DOCUMENT_DELETE_RATE_LIMIT_SCOPE,
    DOCUMENT_DELETE_LIMITS,
    userId,
    request,
    response,
  );
}

/**
 * The shared loop: the windows are checked in order and the first refusal wins,
 * so a caller that is out of budget never reaches the service. The answer goes
 * through the shared helper, so the envelope and the `Retry-After` rounding
 * match every other limited route in the API.
 */
async function consumeOrRefuse(
  rateLimit: RateLimitService,
  scope: string,
  limits: readonly { readonly limit: number; readonly windowSeconds: number }[],
  identifier: string,
  request: AuthenticatedRequest,
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
