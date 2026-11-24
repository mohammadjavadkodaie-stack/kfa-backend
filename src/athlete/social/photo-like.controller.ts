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
import { Public } from '../../common/decorators/public.decorator';
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { refuseWhenOverLimit } from '../../documents/view/view-link-limits';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { parsePhotoId } from '../photos/profile-photo.dto';
import { PhotoLikeService, type PhotoLikeCountView } from './photo-like.service';
import {
  PHOTO_LIKE_COUNT_LIMITS,
  PHOTO_LIKE_COUNT_RATE_LIMIT_SCOPE,
  PHOTO_LIKE_LIMITS,
  PHOTO_LIKE_RATE_LIMIT_SCOPES,
} from './social-limits';

/**
 * Liking an approved profile photo.
 *
 * `PUT` and `DELETE` are authenticated and share one budget per user and per
 * address, so unliking and reliking is charged exactly like liking. The count
 * route is public - it answers a number and nothing else - and is counted per
 * address only.
 *
 * Input is parsed before any counter is charged, so a malformed id costs no
 * budget; a refused request never reaches the service.
 */
@Controller('photos')
export class PhotoLikeController {
  constructor(
    private readonly likes: PhotoLikeService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Put(':photoId/like')
  @HttpCode(HttpStatus.NO_CONTENT)
  async like(
    @Param('photoId') photoId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parsePhotoId(photoId);

    const refusal = await this.writeBudget(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.likes.like(actor, id);
  }

  @Authenticated()
  @Delete(':photoId/like')
  @HttpCode(HttpStatus.NO_CONTENT)
  async unlike(
    @Param('photoId') photoId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parsePhotoId(photoId);

    const refusal = await this.writeBudget(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.likes.unlike(actor, id);
  }

  /** Public on purpose: an engagement number is not personal data. */
  @Public()
  @Get(':photoId/likes/count')
  async count(
    @Param('photoId') photoId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PhotoLikeCountView | ErrorResponseBody> {
    const id = parsePhotoId(photoId);

    const refusal = await refuseWhenOverLimit(
      this.rateLimit,
      PHOTO_LIKE_COUNT_RATE_LIMIT_SCOPE,
      PHOTO_LIKE_COUNT_LIMITS,
      this.address(request),
      request,
      response,
    );

    if (refusal !== null) return refusal;

    return this.likes.count(id);
  }

  /** The user windows first, then the address windows; the first refusal wins. */
  private async writeBudget(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    const byUser = await refuseWhenOverLimit(
      this.rateLimit,
      PHOTO_LIKE_RATE_LIMIT_SCOPES.user,
      PHOTO_LIKE_LIMITS.user,
      userId,
      request,
      response,
    );

    if (byUser !== null) return byUser;

    return refuseWhenOverLimit(
      this.rateLimit,
      PHOTO_LIKE_RATE_LIMIT_SCOPES.address,
      PHOTO_LIKE_LIMITS.address,
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
