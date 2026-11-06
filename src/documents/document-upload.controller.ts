import {
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnprocessableEntityException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { DocumentKind as PrismaDocumentKind } from '@prisma/client';
import { IsIn } from 'class-validator';
import type { Response } from 'express';
import { Authenticated } from '../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import { DocumentIngestError } from './ingest/ingest.errors';
import type { DocumentKind } from './records/identity-document.repository';
import { DocumentUploadService, type DocumentUploadView } from './records/document-upload.service';

/** The one route that takes a file as its body; `configureApp` binds the parser here. */
export const DOCUMENT_UPLOAD_PATH = '/athlete/documents';

/** The only media types the raw parser reads; nothing else is ever buffered. */
export const DOCUMENT_UPLOAD_MEDIA_TYPES = ['image/jpeg', 'image/png'] as const;

/** The counter bucket these limits are kept in, so they cannot collide with any other. */
export const DOCUMENT_UPLOAD_RATE_LIMIT_SCOPE = 'document-upload';

/**
 * Strict per-user limits, checked before the pipeline runs.
 *
 * A burst window stops a client from spending the whole allowance in a minute,
 * and the hourly budget caps the expensive work (scan, sanitize, encrypt, store)
 * one account can ask for. Both are per user - never per address, which a
 * shared network would turn into a denial of service between real users.
 */
export const DOCUMENT_UPLOAD_LIMITS = [
  { limit: 3, windowSeconds: 60 },
  { limit: 10, windowSeconds: 3_600 },
] as const;

/**
 * The closed set of kinds, read from the generated Prisma enum rather than listed.
 *
 * The column is the only source of truth: a value `DocumentKind` gains or loses
 * is accepted or refused here in the same commit, with no second list to keep in
 * step. The copy is frozen so a caller cannot add a kind at runtime.
 */
export const DOCUMENT_KINDS: readonly DocumentKind[] = Object.freeze(
  Object.values(PrismaDocumentKind),
);

/**
 * The only thing a caller may say about the document besides its bytes.
 *
 * The global pipe rejects any other query parameter, so there is no owner, no
 * object key and no file name to supply: the owner is the token and the key is
 * generated server-side.
 */
export class DocumentUploadQueryDto {
  @IsIn(DOCUMENT_KINDS)
  kind!: DocumentKind;
}

/**
 * Uploading one identity document: `POST /athlete/documents?kind=...`.
 *
 * The body is the file itself - raw bytes, not multipart - and the answer is the
 * four fields of `DocumentUploadView`. Everything a client could use to address
 * someone else's document (an owner id, a storage key, a file name) simply has
 * no place to go, so the route cannot be talked into touching another account.
 *
 * Refusals follow the rest of the athlete routes: one generic 401/403 from the
 * guards, one generic 503 when storage, the database or the audit chain fails,
 * and one generic 422 for every ingest or quota refusal - a rejected file and a
 * full account stay indistinguishable from the outside.
 */
@Controller('athlete')
export class DocumentUploadController {
  constructor(
    private readonly uploads: DocumentUploadService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Post('documents')
  @HttpCode(HttpStatus.CREATED)
  async upload(
    @Query() query: DocumentUploadQueryDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<DocumentUploadView | ErrorResponseBody> {
    const actor = this.actor(request);
    // Both checks run before the counters: a body of the refused type was never
    // parsed, so there is nothing to look at and nothing to charge.
    const claimedMime = this.claimedMime(request);
    const bytes = this.body(request);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    try {
      return await this.uploads.upload(actor, { kind: query.kind, bytes, claimedMime });
    } catch (error) {
      if (error instanceof DocumentIngestError) throw new UnprocessableEntityException();

      throw error;
    }
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
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

    if (!DOCUMENT_UPLOAD_MEDIA_TYPES.some((type) => type === essence)) {
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
   * Consumes both windows and reports the refusal, if any.
   *
   * The answer goes through the shared helper, so the envelope and the
   * `Retry-After` rounding match every other limited route in the API.
   */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    for (const limit of DOCUMENT_UPLOAD_LIMITS) {
      const decision = await this.rateLimit.consume({
        scope: DOCUMENT_UPLOAD_RATE_LIMIT_SCOPE,
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
