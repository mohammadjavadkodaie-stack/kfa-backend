import {
  Controller,
  Get,
  HttpStatus,
  InternalServerErrorException,
  Param,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { refuseWhenOverLimit } from '../../documents/view/view-link-limits';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import {
  PROFILE_PHOTO_VIEW_FILE_LIMITS,
  PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE,
} from './profile-photo-view-limits';
import { ProfilePhotoViewService, type ProfilePhotoBytes } from './profile-photo-view.service';

/**
 * Serving the bytes behind a single-use preview link:
 * `GET /photos/view/:token`.
 *
 * The token is the only credential this route accepts, because the client that
 * follows such a link is an `<img>` that cannot attach an `Authorization`
 * header. That is why it is marked `@Public()` and why no session, role or
 * step-up is demanded here: everything the request needs is signed into the
 * token, and `ProfilePhotoViewService.redeem()` re-derives the decision from
 * fresh rows on every call - so a photo rejected after the link was issued
 * stops opening immediately.
 *
 * The answer is the decrypted photo, sent as one `Buffer` with the content type
 * the stored record carries. Nothing about the response is cacheable or
 * shareable, the token is never logged and it never appears in the response.
 *
 * Refusals are deliberately indistinguishable: a bad signature, an expired, a
 * spent or a foreign link, a missing photo and a photo that changed status all
 * answer the same generic 404 with the same headers. A missing secret, missing
 * one-time store, failed audit row or unreadable blob answers one generic 503,
 * and the per-address budget answers the shared 429 envelope.
 */
@Controller('photos/view')
export class ProfilePhotoViewFileController {
  constructor(
    private readonly views: ProfilePhotoViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Public()
  @Get(':token')
  async view(
    @Param('token') token: string,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    // Set before anything can fail, so a refusal and a success differ only in
    // the status, the body and the two content headers.
    this.harden(response);

    const refusal: ErrorResponseBody | null = await refuseWhenOverLimit(
      this.rateLimit,
      PROFILE_PHOTO_VIEW_FILE_RATE_LIMIT_SCOPE,
      PROFILE_PHOTO_VIEW_FILE_LIMITS,
      this.address(request),
      request,
      response,
    );

    if (refusal !== null) {
      // The shared helper already set the status and `Retry-After`.
      response.json(refusal);
      return;
    }

    // The service verifies, spends the nonce, re-checks the rows, writes the
    // trail and only then reads and decrypts the blob.
    this.send(response, await this.views.redeem(token));
  }

  /**
   * The headers every answer of this route carries.
   *
   * `no-store` and `Pragma` because the URL itself is a secret that must not
   * survive in a cache; `nosniff` because the browser must trust the declared
   * type and nothing else; `inline` so an `<img>` renders it while a download
   * still cannot pick its own name; `no-referrer` so the token in the path is
   * not leaked onward; `default-src 'none'; sandbox` because the bytes are
   * user-uploaded content that must never run as a document; and `same-site`
   * so only this site's pages can embed it.
   */
  private harden(response: Response): void {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Disposition', 'inline');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    response.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  }

  /**
   * Writes the photo, or refuses without a byte.
   *
   * The content type is taken only from the record `redeem()` returned - never
   * from the request - and only the two formats the ingest pipeline produces
   * are served. Anything else is an internal fault: generic 500, no body.
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

/** Anything outside the two allowed values is treated as corruption. */
function isServable(contentType: string): boolean {
  return SERVABLE_CONTENT_TYPES.includes(contentType);
}
