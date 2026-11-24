import {
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { Authenticated } from '../../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { refuseWhenOverLimit } from '../../documents/view/view-link-limits';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { parseAthleteProfileId } from '../photos/profile-photo.dto';
import { AthleteFollowService, type AthleteSocialView } from './athlete-follow.service';
import { FOLLOW_LIMITS, FOLLOW_RATE_LIMIT_SCOPES } from './social-limits';

/**
 * Following another athlete, and the follower count of a profile.
 *
 * All three routes carry `@Authenticated` and no role: any signed-in, non-blocked
 * account may follow - the guard refuses a blocked one before this code runs.
 * There is no follower list and no follower id anywhere on the surface.
 *
 * Both write routes spend the same per-user and per-address budget, so unfollow
 * and refollow spam is charged like a first follow. The id is parsed before a
 * counter is charged: a malformed id is the generic 400 and costs nothing.
 */
@Controller('athletes')
export class AthleteFollowController {
  constructor(
    private readonly follows: AthleteFollowService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Get(':profileId/social')
  social(
    @Param('profileId') profileId: string,
    @Req() request: AuthenticatedRequest,
  ): Promise<AthleteSocialView> {
    return this.follows.social(this.actor(request), parseAthleteProfileId(profileId));
  }

  @Authenticated()
  @Put(':profileId/follow')
  @HttpCode(HttpStatus.NO_CONTENT)
  async follow(
    @Param('profileId') profileId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parseAthleteProfileId(profileId);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.follows.follow(actor, id);
  }

  @Authenticated()
  @Delete(':profileId/follow')
  @HttpCode(HttpStatus.NO_CONTENT)
  async unfollow(
    @Param('profileId') profileId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parseAthleteProfileId(profileId);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.follows.unfollow(actor, id);
  }

  /**
   * The user windows first, then the address windows; the first refusal wins.
   * The answer goes through the shared helper, so the envelope and the
   * `Retry-After` rounding match every other limited route in the API.
   */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    const byUser = await refuseWhenOverLimit(
      this.rateLimit,
      FOLLOW_RATE_LIMIT_SCOPES.user,
      FOLLOW_LIMITS.user,
      userId,
      request,
      response,
    );

    if (byUser !== null) return byUser;

    return refuseWhenOverLimit(
      this.rateLimit,
      FOLLOW_RATE_LIMIT_SCOPES.address,
      FOLLOW_LIMITS.address,
      this.address(request),
      request,
      response,
    );
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }

  /** The resolved client address, already unwrapped by the trusted proxy setup. */
  private address(request: AuthenticatedRequest): string {
    return request.ip ?? request.socket?.remoteAddress ?? 'unknown';
  }
}
