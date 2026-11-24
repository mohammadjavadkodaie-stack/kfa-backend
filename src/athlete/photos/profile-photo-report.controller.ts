import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { Authenticated } from '../../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { writeTooManyRequests, type ErrorResponseBody } from '../../common/errors/error-response';
import { getRequestId } from '../../common/middleware/request-id.middleware';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { parsePhotoId } from './profile-photo.dto';
import { parsePhotoReport } from './profile-photo-report.dto';
import { ProfilePhotoReportService } from './profile-photo-report.service';

/** Counter bucket, kept apart from uploads, reads and preview links. */
export const PROFILE_PHOTO_REPORT_RATE_LIMIT_SCOPE = 'profile-photo-report';

/**
 * Reporting is cheap but it is a write, and a report must not become a way to
 * flood the staff list. Both windows are per user, never per address.
 */
export const PROFILE_PHOTO_REPORT_LIMITS = [
  { limit: 5, windowSeconds: 60 },
  { limit: 20, windowSeconds: 3_600 },
] as const;

/**
 * `POST /photos/:photoId/report`.
 *
 * Any authenticated account may report a photo - USER or ATHLETE - so the
 * controller declares `@Authenticated` and no role: the global guard already
 * refused an anonymous caller and refuses a route carrying no marker at all,
 * while the service refuses the owner and anything that is not APPROVED. The
 * answer is always an empty 204, whether the report was new, a duplicate, or
 * (for a photo the caller cannot see) refused as 404.
 */
@Controller('photos')
export class ProfilePhotoReportController {
  constructor(
    private readonly reports: ProfilePhotoReportService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Post(':photoId/report')
  @HttpCode(HttpStatus.NO_CONTENT)
  async report(
    @Param('photoId') photoId: string,
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);
    // Input checks before the counters: a body outside the schema was never
    // going to be written, so there is nothing to charge for it.
    const input = parsePhotoReport(body);
    const id = parsePhotoId(photoId);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.reports.report(actor, id, input);
  }

  /** Consumes both per-user windows; the first refusal wins. */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    for (const limit of PROFILE_PHOTO_REPORT_LIMITS) {
      const decision = await this.rateLimit.consume({
        scope: PROFILE_PHOTO_REPORT_RATE_LIMIT_SCOPE,
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
}
