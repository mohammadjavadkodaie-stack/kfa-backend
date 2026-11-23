import {
  BadRequestException,
  Controller,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Req,
  Res,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import type { RawBodyRequest } from '../common/middleware/raw-body.middleware';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import { BillingWebhookService } from './billing-webhook.service';

/** Route prefix. `app.setup.ts` binds the raw body reader to it. */
export const BILLING_WEBHOOK_PATH = 'billing/webhook';

/**
 * Largest delivery accepted, in bytes. A provider notification is a few
 * kilobytes; this bounds what one address can make the signature check hash.
 */
export const BILLING_WEBHOOK_MAX_BODY_BYTES = 64 * 1024;

/** Counter bucket, kept apart from every other limited route. */
export const BILLING_WEBHOOK_RATE_LIMIT_SCOPE = 'billing-webhook';

/**
 * Per-address limits.
 *
 * A provider retries a delivery it could not confirm, so the minute budget has to
 * survive a backlog, while a single address still cannot use this route as free
 * CPU for signature checks. The hourly window is the backstop.
 */
export const BILLING_WEBHOOK_RATE_LIMITS = [
  { limit: 120, windowSeconds: 60 },
  { limit: 2_000, windowSeconds: 3_600 },
] as const;

/** Provider names are short enum-like words; anything else is not a route. */
const PROVIDER_NAME = /^[A-Za-z0-9_-]{1,32}$/;

/** The bucket a request with no resolvable address is counted in. */
const UNKNOWN_ADDRESS = 'unknown';

/**
 * Inbound payment notifications: `POST /billing/webhook/:provider`.
 *
 * Public by necessity - the caller is a payment provider, not a signed-in user -
 * so nothing in the request is trusted. The body is only bytes until the
 * provider's verifier accepts the signature, and the amount and status that
 * decide a subscription come from the stored payment row, never from this body.
 *
 * Refusals stay generic: 404 for a provider that has no verifier (nothing is
 * read), 400 for a body this route cannot accept, 429 with the shared envelope
 * when the address is over budget, and 503 when the shared store or the database
 * is unreachable - never a reason, a key or an internal name.
 */
@Controller(BILLING_WEBHOOK_PATH)
export class BillingWebhookController {
  constructor(
    private readonly webhooks: BillingWebhookService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Public()
  @Post(':provider')
  @HttpCode(HttpStatus.ACCEPTED)
  async receive(
    @Param('provider') provider: string,
    @Req() request: RawBodyRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<{ readonly accepted: boolean } | ErrorResponseBody> {
    const refusal = await this.refuseWhenOverLimit(request, response);

    if (refusal !== null) return refusal;

    const name = this.providerName(provider);
    const outcome = await this.webhooks.handle(name, this.rawBody(request), request.headers);

    // A provider with no verifier is answered like any unknown path: a
    // misconfiguration then shows up as a delivery the provider keeps retrying,
    // instead of a 2xx that silently drops payments.
    if (!outcome.knownProvider) throw new NotFoundException();

    // The verifier could not reach PayPal (or its own clock): ask for the same
    // delivery again. Answering 2xx here would drop a payment nobody confirmed.
    if (outcome.retryLater) throw new ServiceUnavailableException();

    // A forged signature is stored as nothing and audited; the provider gets a
    // handled answer so it does not resend the same bad payload forever.
    return { accepted: outcome.accepted };
  }

  /**
   * The provider name as the `PaymentProvider` enum spells it, or a 404 when the
   * segment could not name one. Matching the enum keeps the verifier map and the
   * stored payment row keyed by the same value.
   */
  private providerName(provider: string): string {
    if (!PROVIDER_NAME.test(provider)) throw new NotFoundException();

    return provider.toUpperCase();
  }

  /**
   * The exact bytes the provider signed. The JSON parser keeps them; a body it
   * did not parse (another media type, or none) has nothing to verify, so the
   * request stops here with the generic 400 rather than an empty signature check.
   */
  private rawBody(request: RawBodyRequest): Buffer {
    const body = request.rawBody;

    if (!Buffer.isBuffer(body) || body.length === 0) throw new BadRequestException();

    return body;
  }

  /**
   * Consumes both windows and reports the refusal, if any.
   *
   * The address is the tracker here: there is no account yet, and hashing it
   * inside `RateLimitService` keeps the raw address out of Redis and the logs.
   */
  private async refuseWhenOverLimit(
    request: RawBodyRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    const address = request.ip ?? UNKNOWN_ADDRESS;

    for (const limit of BILLING_WEBHOOK_RATE_LIMITS) {
      const decision = await this.rateLimit.consume({
        scope: BILLING_WEBHOOK_RATE_LIMIT_SCOPE,
        identifier: address,
        ...limit,
      });

      if (!decision.allowed) {
        return writeTooManyRequests(response, request, decision.retryAfterSeconds);
      }
    }

    return null;
  }
}
