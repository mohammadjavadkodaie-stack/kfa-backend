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
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import {
  PROFILE_PHOTO_VIEW_LINK_LIMITS,
  PROFILE_PHOTO_VIEW_LINK_RATE_LIMIT_SCOPE,
} from '../athlete/photos/profile-photo-view-limits';
import {
  ProfilePhotoViewService,
  type ProfilePhotoPreviewLink,
} from '../athlete/photos/profile-photo-view.service';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { getRequestId } from '../common/middleware/request-id.middleware';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import {
  parseRejectPhoto,
  PhotoReviewParamsDto,
  PhotoReviewQueueQueryDto,
} from './staff-photo-review.dto';
import {
  StaffPhotoReviewService,
  type PhotoReviewDecisionResult,
  type PhotoReviewQueuePage,
} from './staff-photo-review.service';

/**
 * The profile-photo moderation queue: `GET /staff/photo-reviews`,
 * `POST /staff/photo-reviews/:photoId/approve` and
 * `POST /staff/photo-reviews/:photoId/reject`.
 *
 * The guard stack is the staff review stack:
 *
 * - the global `AuthGuard` resolves the caller;
 * - the global `StaffGateGuard` keeps a staff session that never proved a second
 *   factor out of the whole controller;
 * - `@Roles(ADMIN, OWNER)` keeps every USER and ATHLETE out;
 * - `@RequireStepUp()` additionally covers the two decisions.
 *
 * Listing is a read of metadata, so the five-minute window is not demanded
 * there - the gate the session already passed is enough, and no image bytes and
 * no view link are returned.
 */
@Controller('staff/photo-reviews')
export class StaffPhotoReviewController {
  constructor(
    private readonly reviews: StaffPhotoReviewService,
    private readonly views: ProfilePhotoViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  /** One page of PENDING photos, oldest first; an empty page carries no cursor. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get()
  async list(@Query() query: PhotoReviewQueueQueryDto): Promise<PhotoReviewQueuePage> {
    return this.reviews.listQueue(query);
  }

  /** Records an approval; 409 when someone decided first. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':photoId/approve')
  @HttpCode(HttpStatus.OK)
  async approve(
    @Param() params: PhotoReviewParamsDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<PhotoReviewDecisionResult> {
    return this.reviews.decide(
      this.actor(request),
      params.photoId,
      { status: 'APPROVED' },
      this.context(request),
    );
  }

  /** Records a rejection with the reviewer's optional reason; 409 on a race. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':photoId/reject')
  @HttpCode(HttpStatus.OK)
  async reject(
    @Param() params: PhotoReviewParamsDto,
    // Optional and at most one field; zod is the whole gate, so the pipe skips it.
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<PhotoReviewDecisionResult> {
    const decision = parseRejectPhoto(body);

    return this.reviews.decide(
      this.actor(request),
      params.photoId,
      { status: 'REJECTED', reason: decision.reason },
      this.context(request),
    );
  }

  /**
   * A short-lived, single-use link a reviewer may use to look at one photo:
   * `POST /staff/photo-reviews/:photoId/view-link`.
   *
   * Step-up is demanded here as well as on the decisions: a preview hands out
   * the image itself, not just metadata. The link may open a PENDING or an
   * APPROVED photo - REJECTED is refused - and the status is re-read when the
   * link is spent, so a photo rejected in between stops opening. Both the issue
   * and the serve write an audit row.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':photoId/view-link')
  @HttpCode(HttpStatus.CREATED)
  async issueViewLink(
    @Param() params: PhotoReviewParamsDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ProfilePhotoPreviewLink | ErrorResponseBody> {
    const actor = this.actor(request);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    return this.views.issueStaffLink(actor, params.photoId);
  }

  /** Consumes the shared preview-link windows; the first refusal wins. */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    for (const limit of PROFILE_PHOTO_VIEW_LINK_LIMITS) {
      const decision = await this.rateLimit.consume({
        scope: PROFILE_PHOTO_VIEW_LINK_RATE_LIMIT_SCOPE,
        identifier: userId,
        ...limit,
      });

      if (!decision.allowed) {
        return writeTooManyRequests(response, request, decision.retryAfterSeconds);
      }
    }

    return null;
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
