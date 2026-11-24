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
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import { getRequestId } from '../common/middleware/request-id.middleware';
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
  constructor(private readonly reviews: StaffPhotoReviewService) {}

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
