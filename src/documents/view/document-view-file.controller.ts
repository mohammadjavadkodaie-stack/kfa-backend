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
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentViewService, type DocumentViewBytes } from './document-view.service';
import { refuseViewFileWhenOverLimit } from './view-link-limits';

/**
 * Serving the bytes behind a single-use link: `GET /documents/view/:token`.
 *
 * The token is the only credential this route accepts, because the client that
 * follows a view link is an `<img>` (or a download) that cannot attach an
 * `Authorization` header. That is why it is marked `@Public()` and why no
 * session, role or step-up is demanded here: everything the request needs is
 * signed into the token, and `DocumentViewService.redeem()` re-derives the
 * decision from fresh rows on every call. It is the same decision the issue
 * routes already make - the basis (owner or staff) travels inside the token.
 *
 * The answer is the decrypted document, sent as one `Buffer` with the
 * content type the stored record carries. Nothing about the response is
 * cacheable or shareable, the token is never logged (see
 * `src/logging/request-path.ts`) and it never appears in the response.
 *
 * Refusals are deliberately indistinguishable: a bad signature, an expired, a
 * spent or a foreign link, and a missing document all answer the same 404 with
 * the same headers, so a caller cannot use this route to probe either the
 * links or the documents. A missing secret, missing one-time store, failed
 * audit row or unreadable blob answers one generic 503 with no bytes, and the
 * per-address budget the shared 429 envelope.
 */
@Controller('documents/view')
export class DocumentViewFileController {
  constructor(
    private readonly views: DocumentViewService,
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

    const refusal = await refuseViewFileWhenOverLimit(
      this.rateLimit,
      this.address(request),
      request,
      response,
    );

    if (refusal !== null) {
      // `writeTooManyRequests` already set the status and `Retry-After`.
      response.json(refusal);
      return;
    }

    // The service is unchanged: it verifies, spends the nonce, re-checks the
    // rows, writes the trail and only then reads and decrypts the blob.
    this.send(response, await this.views.redeem(token));
  }

  /**
   * The headers every answer of this route carries.
   *
   * `no-store` and `Pragma` because the body is a private document and the URL
   * itself is a secret that must not survive in a cache; `nosniff` because the
   * browser must trust the declared type and nothing else; `inline` so an
   * `<img>` renders it while a download still cannot pick its own name;
   * `no-referrer` so the token in the path is not leaked onward from the page;
   * `default-src 'none'; sandbox` because the bytes are user-uploaded content
   * that must never run as a document; and `same-site` so only this site's
   * pages can embed it.
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
   * Writes the document, or refuses without a byte.
   *
   * The content type is taken only from the record `redeem()` returned - never
   * from the request - and only the two formats the ingest pipeline produces
   * are served. A row that somehow carries anything else is an internal fault:
   * generic 500, no body, no partial write.
   */
  private send(response: Response, view: DocumentViewBytes): void {
    if (!isServable(view.contentType)) throw new InternalServerErrorException();

    response.setHeader('Content-Type', view.contentType);
    response.setHeader('Content-Length', String(view.bytes.length));
    response.status(HttpStatus.OK);
    // One buffer, no streaming: the whole document or nothing.
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
