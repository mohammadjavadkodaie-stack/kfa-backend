import {
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UnprocessableEntityException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import type { Response } from 'express';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import type { PolicySubject } from '../../auth/policy/access-policy';
import type { AccessPolicyContext } from '../../auth/policy/access-policy.service';
import { Role } from '../../auth/roles';
import { writeTooManyRequests, type ErrorResponseBody } from '../../common/errors/error-response';
import { getRequestId } from '../../common/middleware/request-id.middleware';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentIngestError } from '../../documents/ingest/ingest.errors';
import { parsePhotoId, parsePhotoUploadQuery } from './profile-photo.dto';
import {
  PROFILE_PHOTO_VIEW_LINK_LIMITS,
  PROFILE_PHOTO_VIEW_LINK_RATE_LIMIT_SCOPE,
} from './profile-photo-view-limits';
import {
  ProfilePhotoViewService,
  type ProfilePhotoPreviewLink,
} from './profile-photo-view.service';
import {
  ProfilePhotosService,
  type ProfilePhotoListView,
  type ProfilePhotoView,
} from './profile-photos.service';

/** The one route that takes a photo as its body; `configureApp` binds the parser here. */
export const PROFILE_PHOTOS_UPLOAD_PATH = '/athlete/profile/photos';

/** The only media types the raw parser reads; nothing else is ever buffered. */
export const PROFILE_PHOTO_MEDIA_TYPES = ['image/jpeg', 'image/png'] as const;

/** Counter buckets, kept apart from every other scope so limits cannot collide. */
export const PROFILE_PHOTO_UPLOAD_RATE_LIMIT_SCOPE = 'athlete-profile-photo-upload';
export const PROFILE_PHOTO_READ_RATE_LIMIT_SCOPE = 'athlete-profile-photo-read';

/**
 * Per-user limits, checked before any expensive work.
 *
 * Uploads cost a scan, an encryption and a write, so the burst window is tighter
 * than the one for reads. Both are per user - never per address, which a shared
 * network would turn into a denial of service between real users.
 */
export const PROFILE_PHOTO_UPLOAD_LIMITS = [
  { limit: 5, windowSeconds: 60 },
  { limit: 20, windowSeconds: 3_600 },
] as const;

export const PROFILE_PHOTO_READ_LIMITS = [{ limit: 60, windowSeconds: 60 }] as const;

/**
 * The caller's own profile photos: `POST /athlete/profile/photos` to upload,
 * `GET /athlete/profile/photos` for the list and `GET .../:photoId` for one.
 *
 * The body is the photo itself - raw bytes, not multipart - and the caption is
 * the one query parameter, validated and sanitized before the service sees it.
 * There is no owner parameter, no status parameter and no file name: the owner is
 * the verified principal and the status is decided by the database default, so
 * the route has no way to create an approved photo or to address another account.
 *
 * Refusals follow the rest of the athlete routes: one generic 401/403 from the
 * guards, one generic 503 when storage, the database or the audit chain fails,
 * and one generic 422 for every ingest or quota refusal - a rejected file and a
 * full account stay indistinguishable from the outside.
 */
@Controller('athlete/profile/photos')
@Roles(Role.ATHLETE)
export class ProfilePhotosController {
  constructor(
    private readonly photos: ProfilePhotosService,
    private readonly views: ProfilePhotoViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async upload(
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ProfilePhotoView | ErrorResponseBody> {
    const actor = this.actor(request);
    // Input checks before the counters: a body of the refused type or a malformed
    // caption was never going to reach the pipeline, so there is nothing to charge.
    const claimedMime = this.claimedMime(request);
    const bytes = this.body(request);
    const caption = parsePhotoUploadQuery(request.query).caption;

    const refusal = await this.refuseWhenOverLimit(
      actor.id,
      request,
      response,
      PROFILE_PHOTO_UPLOAD_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_UPLOAD_LIMITS,
    );

    if (refusal !== null) return refusal;

    try {
      const view = await this.photos.upload(
        actor,
        { bytes, claimedMime, caption },
        this.context(request),
      );

      response.setHeader('Location', `${PROFILE_PHOTOS_UPLOAD_PATH}/${view.id}`);

      return view;
    } catch (error) {
      if (error instanceof DocumentIngestError) throw new UnprocessableEntityException();

      throw error;
    }
  }

  @Get()
  async list(
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ProfilePhotoListView | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await this.refuseWhenOverLimit(
      actor.id,
      request,
      response,
      PROFILE_PHOTO_READ_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_READ_LIMITS,
    );

    if (refusal !== null) return refusal;

    return this.photos.list(actor);
  }

  /**
   * One own photo. A malformed id is a generic 400 and a foreign id is the same
   * generic 404 as a missing one, so the route never confirms what exists.
   */
  @Get(':photoId')
  async read(
    @Param('photoId') photoId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ProfilePhotoView | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parsePhotoId(photoId);
    const refusal = await this.refuseWhenOverLimit(
      actor.id,
      request,
      response,
      PROFILE_PHOTO_READ_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_READ_LIMITS,
    );

    if (refusal !== null) return refusal;

    return this.photos.read(actor, id);
  }

  /**
   * A short-lived, single-use link to one own photo: `POST .../:photoId/view-link`.
   *
   * The owner may open their own photo at any status - a PENDING upload is what
   * they just sent and a REJECTED one is what they may want to replace - but the
   * link is not a session: it is signed for that one photo and that one viewer,
   * can be spent once, and the status is re-checked when it is spent. A foreign
   * id answers the same generic 404 as a missing one.
   */
  @Post(':photoId/view-link')
  @HttpCode(HttpStatus.CREATED)
  async issueViewLink(
    @Param('photoId') photoId: string,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ProfilePhotoPreviewLink | ErrorResponseBody> {
    const actor = this.actor(request);
    const id = parsePhotoId(photoId);
    const refusal = await this.refuseWhenOverLimit(
      actor.id,
      request,
      response,
      PROFILE_PHOTO_VIEW_LINK_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_VIEW_LINK_LIMITS,
    );

    if (refusal !== null) return refusal;

    return this.views.issueOwnerLink(actor, id);
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

  /**
   * The declared type, which is the only thing the header is used for: the
   * pipeline still decides the real format from the magic bytes and refuses a
   * claim that contradicts them. A missing or non-image type never gets that far.
   */
  private claimedMime(request: AuthenticatedRequest): string {
    const header = request.headers['content-type'];

    if (typeof header !== 'string') throw new UnsupportedMediaTypeException();

    const essence = header.split(';')[0]?.trim().toLowerCase();

    if (!PROFILE_PHOTO_MEDIA_TYPES.some((type) => type === essence)) {
      throw new UnsupportedMediaTypeException();
    }

    return header;
  }

  /**
   * The parser leaves a Buffer for the two image types and nothing for the rest.
   * An empty body would only be refused again by the size window in the pipeline,
   * so it stops here, with the same generic answer.
   */
  private body(request: AuthenticatedRequest): Buffer {
    const body: unknown = request.body;

    if (!Buffer.isBuffer(body) || body.length === 0) throw new UnprocessableEntityException();

    return body;
  }

  /**
   * Consumes the windows in order and reports the first refusal.
   *
   * The answer goes through the shared helper, so the envelope and the
   * `Retry-After` rounding match every other limited route in the API.
   */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
    scope: string,
    limits: readonly { readonly limit: number; readonly windowSeconds: number }[],
  ): Promise<ErrorResponseBody | null> {
    for (const limit of limits) {
      const decision = await this.rateLimit.consume({
        scope,
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
