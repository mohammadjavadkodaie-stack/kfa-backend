import {
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Body,
  Param,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { Authenticated } from '../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { ErrorResponseBody } from '../common/errors/error-response';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import {
  refuseDocumentDeleteWhenOverLimit,
  refuseDocumentListWhenOverLimit,
} from './owner-document-limits';
import { DocumentDeleteParamsDto, NoDocumentParametersDto } from './owner-documents.dto';
import type { OwnedDocumentList } from './records/owner-documents.service';
import { OwnerDocumentsService } from './records/owner-documents.service';

/**
 * The two routes that act on the caller's own documents:
 * `GET /athlete/documents` and `DELETE /athlete/documents/:documentId`.
 *
 * Only `@Authenticated` - every signed-in role reaches them - but neither route
 * names an owner: the account is the verified principal, so a staff member who
 * calls them acts on their own documents and on nobody else's. There is no
 * staff variant here; cross-account access stays on the staff routes, where
 * StaffGate and a step-up are demanded.
 *
 * The list answers five fields per document and never the object key, the
 * digest, the envelope, the owner id or the quota. The delete answers 204 and
 * one generic 404 for a missing, foreign or already deleted id, so the route
 * cannot be used to discover which ids exist.
 *
 * Refusals follow the rest of the athlete routes: one generic 401/403 from the
 * guards, one generic 404 that is the same for every document the caller cannot
 * delete, one generic 503 when the database or the audit chain fails, a 400 for
 * anything the pipe does not recognise, and the shared 429 envelope with
 * `Retry-After` when the per-user budget is spent.
 */
@Controller('athlete')
export class OwnerDocumentsController {
  constructor(
    private readonly documents: OwnerDocumentsService,
    private readonly rateLimit: RateLimitService,
  ) {}

  /**
   * Both parameters are declared only to be refused: the classes carry no
   * fields, so the global pipe answers 400 to any query or body key instead of
   * ignoring it.
   */
  @Authenticated()
  @Get('documents')
  async list(
    @Query() _query: NoDocumentParametersDto,
    @Body() _body: NoDocumentParametersDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<OwnedDocumentList | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await refuseDocumentListWhenOverLimit(
      this.rateLimit,
      actor.id,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    return this.documents.list(actor);
  }

  /** A 204 carries no body; the refusal path still writes the shared envelope. */
  @Authenticated()
  @Delete('documents/:documentId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param() params: DocumentDeleteParamsDto,
    @Query() _query: NoDocumentParametersDto,
    @Body() _body: NoDocumentParametersDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ErrorResponseBody | undefined> {
    const actor = this.actor(request);
    const refusal = await refuseDocumentDeleteWhenOverLimit(
      this.rateLimit,
      actor.id,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    await this.documents.delete(actor, params.documentId);

    return undefined;
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }
}
