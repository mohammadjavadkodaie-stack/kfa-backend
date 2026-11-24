import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import { getRequestId } from '../common/middleware/request-id.middleware';
import {
  RejectReviewDto,
  ReviewProfileParamsDto,
  ReviewQueueQueryDto,
  parseApproveReview,
} from './staff-review.dto';
import {
  StaffReviewService,
  type ReviewDecisionResult,
  type ReviewDetailView,
  type ReviewQueuePage,
} from './staff-review.service';

/**
 * The review queue and its two decisions: `GET /staff/reviews`,
 * `GET /staff/reviews/:profileId`, `POST /staff/reviews/:profileId/approve`
 * and `POST /staff/reviews/:profileId/reject`.
 *
 * The guard stack is the view-link stack, minus the parts a decision does not
 * need:
 *
 * - the global `AuthGuard` resolves the caller;
 * - the global `StaffGateGuard` keeps a staff session that never proved a second
 *   factor out of the whole controller;
 * - `@Roles(ADMIN, OWNER)` keeps every USER and ATHLETE out;
 * - `@RequireStepUp()` additionally covers the two decisions, so a session that
 *   proved the factor once this morning cannot change a life today.
 *
 * Listing is a read, so the five-minute window is not demanded there - the gate
 * the session already passed is enough, and no document bytes are returned.
 */
@Controller('staff/reviews')
export class StaffReviewController {
  constructor(private readonly reviews: StaffReviewService) {}

  /** One page of the queue; an empty page carries no cursor to follow. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get()
  async list(@Query() query: ReviewQueueQueryDto): Promise<ReviewQueuePage> {
    return this.reviews.listQueue(query);
  }

  /** The declared profile data and the documents' metadata; the bytes stay behind view links. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get(':profileId')
  async detail(
    @Param() params: ReviewProfileParamsDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<ReviewDetailView> {
    return this.reviews.readDetail(this.actor(request), params.profileId, this.context(request));
  }

  /** Records an approval and tells the athlete; 409 when someone decided first. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':profileId/approve')
  @HttpCode(HttpStatus.OK)
  async approve(
    @Param() params: ReviewProfileParamsDto,
    // Optional and at most one flag; zod is the whole gate, so the pipe skips it.
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<ReviewDecisionResult> {
    const approval = parseApproveReview(body);

    return this.reviews.decide(
      this.actor(request),
      params.profileId,
      {
        status: 'APPROVED',
        acknowledgeNoSubscription: approval.acknowledgeNoSubscription,
      },
      this.context(request),
    );
  }

  /** Records a rejection with the reviewer's reason; 409 when someone decided first. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':profileId/reject')
  @HttpCode(HttpStatus.OK)
  async reject(
    @Param() params: ReviewProfileParamsDto,
    @Body() body: RejectReviewDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<ReviewDecisionResult> {
    return this.reviews.decide(
      this.actor(request),
      params.profileId,
      { status: 'REJECTED', reason: body.reason },
      this.context(request),
    );
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }

  /** Request facts an audit row may carry; the service hashes the IP. */
  private context(request: AuthenticatedRequest): AccessPolicyContext {
    return { requestId: getRequestId(request), ip: request.ip ?? null };
  }
}
