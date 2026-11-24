import {
  Controller,
  Get,
  HttpStatus,
  InternalServerErrorException,
  Param,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { refuseWhenOverLimit } from '../../documents/view/view-link-limits';
import {
  parseAthleteProfileId,
  parsePhotoId,
  parsePublicPhotoListQuery,
} from './profile-photo.dto';
import {
  PROFILE_PHOTO_PUBLIC_FILE_LIMITS,
  PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE,
  PROFILE_PHOTO_PUBLIC_LIST_LIMITS,
  PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE,
} from './profile-photo-view-limits';
import {
  ProfilePhotoViewService,
  type ApprovedPhotoPage,
  type ProfilePhotoBytes,
} from './profile-photo-view.service';

/**
 * The unauthenticated profile-photo surface.
 *
 * Two routes:
 *
 * - `GET /public/photos/:photoId` returns one photo's bytes, and only when the
 *   row is APPROVED *at the moment of the request*;
 * - `GET /public/athlete-profiles/:athleteProfileId/photos` lists one profile's
 *   approved photos, metadata only.
 *
 * Both are marked `@Public()` explicitly: the guard's default is deny, so no
 * route becomes reachable by accident. Neither route takes a caller identity,
 * so both spend a per-address budget before doing any work.
 *
 * A missing photo, a PENDING one, a REJECTED one and a malformed id are all the
 * same generic 404 (the malformed id is a 400 before a query runs, which
 * discloses nothing). No object key, key id or digest is ever echoed.
 */
@Controller('public')
export class PublicProfilePhotosController {
  constructor(
    private readonly views: ProfilePhotoViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Public()
  @Get('photos/:photoId')
  async read(
    @Param('photoId') photoId: string,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    // Set before anything can fail, so a refusal and a success differ only in
    // the status, the body and the two content headers.
    this.harden(response);

    const refusal = await this.refuse(
      PROFILE_PHOTO_PUBLIC_FILE_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_PUBLIC_FILE_LIMITS,
      request,
      response,
    );

    if (refusal !== null) {
      // The shared helper already set the status and `Retry-After`.
      response.json(refusal);
      return;
    }

    this.send(response, await this.views.readApproved(parsePhotoId(photoId)));
  }

  @Public()
  @Get('athlete-profiles/:athleteProfileId/photos')
  async list(
    @Param('athleteProfileId') athleteProfileId: string,
    @Query() query: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ApprovedPhotoPage | ErrorResponseBody> {
    const profileId = parseAthleteProfileId(athleteProfileId);
    const page = parsePublicPhotoListQuery(query);

    const refusal = await this.refuse(
      PROFILE_PHOTO_PUBLIC_LIST_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_PUBLIC_LIST_LIMITS,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    // Metadata still describes a person: the answer is per-request only.
    response.setHeader('Cache-Control', 'no-store');

    return this.views.listApproved(profileId, {
      limit: page.limit,
      ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
    });
  }

  /** Consumes the per-address budget; the caller's id is not known here. */
  private refuse(
    scope: string,
    limits: readonly { readonly limit: number; readonly windowSeconds: number }[],
    request: Request,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    return refuseWhenOverLimit(
      this.rateLimit,
      scope,
      limits,
      this.address(request),
      request,
      response,
    );
  }

  /**
   * The headers every answer of this route carries.
   *
   * `no-store` and `Pragma` because an approval can be withdrawn and the next
   * answer must reflect that; `nosniff` because the browser must trust the
   * declared type and nothing else; `inline` so an `<img>` renders it;
   * `no-referrer` because the URL may be shared; `default-src 'none'; sandbox`
   * because the bytes are user-uploaded content that must never run as a
   * document. `cross-origin` (not `same-site`, as on the private route): these
   * bytes are public on purpose and the app is served from another origin.
   */
  private harden(response: Response): void {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Disposition', 'inline');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    response.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }

  /**
   * Writes the photo, or refuses without a byte.
   *
   * The content type is taken only from the stored record - never from the
   * request - and only the two formats the ingest pipeline produces are served.
   * A row that somehow carries anything else is an internal fault: generic 500,
   * no body, no partial write.
   */
  private send(response: Response, view: ProfilePhotoBytes): void {
    if (!isServable(view.contentType)) throw new InternalServerErrorException();

    response.setHeader('Content-Type', view.contentType);
    response.setHeader('Content-Length', String(view.bytes.length));
    response.status(HttpStatus.OK);
    // One buffer, no streaming: the whole photo or nothing.
    response.end(view.bytes);
  }

  /** The resolved client address, already unwrapped by the trusted proxy setup. */
  private address(request: Request): string {
    return request.ip ?? request.socket?.remoteAddress ?? 'unknown';
  }
}

/** The only two media types the record may name, exactly as ingest writes them. */
const SERVABLE_CONTENT_TYPES: readonly string[] = ['image/jpeg', 'image/png'];

/**
 * A stored row is the only source of the content type, but it is still checked:
 * anything outside the two allowed values is treated as corruption and refused.
 */
function isServable(contentType: string): boolean {
  return SERVABLE_CONTENT_TYPES.includes(contentType);
}
