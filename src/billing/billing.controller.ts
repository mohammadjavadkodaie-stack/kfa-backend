import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Patch,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { IsIn, Matches } from 'class-validator';
import type { PaymentProvider } from '@prisma/client';
import type { Response } from 'express';
import { Authenticated } from '../auth/decorators/authenticated.decorator';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { getRequestId } from '../common/middleware/request-id.middleware';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import {
  BillingCheckoutService,
  type CheckoutView,
  type PlanView,
  type SubscriptionView,
} from './billing-checkout.service';
import { PRICE_USD_PATTERN } from './billing-plan';

/** Counter bucket for starting a checkout, kept apart from every other route. */
export const CHECKOUT_RATE_LIMIT_SCOPE = 'billing-checkout';

/**
 * A payment page is created per attempt and each attempt costs a provider call,
 * so the budget is per account: enough for retries and a new method, not enough
 * to use the endpoint as a free invoice factory.
 */
export const CHECKOUT_LIMITS = [
  { limit: 5, windowSeconds: 600 },
  { limit: 20, windowSeconds: 3_600 },
] as const;

/** The providers this API can sell through; anything else is a 400. */
export const PAYMENT_PROVIDERS = ['NOWPAYMENTS', 'PAYPAL'] as const;

export class CheckoutDto {
  @IsIn(PAYMENT_PROVIDERS)
  provider!: PaymentProvider;
}

/** A positive decimal with at most two fraction digits, as a string. */
export class PriceDto {
  @Matches(PRICE_USD_PATTERN, { message: 'priceUsd must be a positive decimal with 2 decimals' })
  priceUsd!: string;
}

/**
 * The athlete's side of billing: what it costs, what they have, and how to pay.
 *
 * Every route is authenticated. Nothing here takes an amount: the price is the
 * stored one, and only the staff route below can change it.
 */
@Controller('billing')
export class BillingController {
  constructor(
    private readonly billing: BillingCheckoutService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Get('plans')
  async plans(): Promise<PlanView[]> {
    return this.billing.catalogue();
  }

  @Authenticated()
  @Get('subscription')
  async subscription(@Req() request: AuthenticatedRequest): Promise<SubscriptionView> {
    return this.billing.subscription(this.actor(request).id);
  }

  @Authenticated()
  @Post('checkout')
  @HttpCode(201)
  async checkout(
    @Body() body: CheckoutDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<CheckoutView | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    return this.billing.checkout(actor, body.provider, getRequestId(request));
  }

  /**
   * Price change: staff only, and only with a fresh second factor. The amount
   * affects every future payment, so the step-up is what keeps a borrowed
   * session from repricing the offer.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Patch('price')
  @HttpCode(200)
  async changePrice(
    @Body() body: PriceDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response?: Response,
  ): Promise<PlanView | { status: 'PENDING'; pendingApprovalId: string }> {
    const result = await this.billing.changePrice(
      this.actor(request),
      body.priceUsd,
      getRequestId(request),
    );
    if ('status' in result && result.status === 'PENDING') response?.status(202);
    return result;
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }

  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    for (const limit of CHECKOUT_LIMITS) {
      const decision = await this.rateLimit.consume({
        scope: CHECKOUT_RATE_LIMIT_SCOPE,
        identifier: userId,
        ...limit,
      });

      if (!decision.allowed) {
        return writeTooManyRequests(response, request, decision.retryAfterSeconds);
      }
    }

    return null;
  }
}
