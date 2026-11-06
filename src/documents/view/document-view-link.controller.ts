import {
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
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentViewLinkParamsDto } from './document-view-link.dto';
import { DocumentViewService, type DocumentViewLink } from './document-view.service';
import { refuseViewLinkWhenOverLimit } from './view-link-limits';

/**
 * Issuing a single-use link to one of the caller's own documents:
 * `POST /athlete/documents/:documentId/view-link`.
 *
 * The answer is the short-lived token and its lifetime, nothing else: no object
 * key, no file name, no bytes and no permanent URL. The bytes are served by a
 * separate route (stage 4.4b-2), so this one only decides and records.
 *
 * `staffVerified` is deliberately never set here. The service derives the basis
 * from the rows - ownership first - so this route can only ever produce the
 * owner basis, whatever role its caller holds. A staff member who needs another
 * account's document has to use the staff route, which is the only place where
 * StaffGate and a step-up are demanded.
 *
 * Refusals follow the rest of the athlete routes: one generic 401/403 from the
 * guards, one generic 404 that is the same for a missing and a foreign document,
 * one generic 503 when the secret, the store, the database or the audit chain
 * fails, and the shared 429 envelope when the per-user budget is spent.
 */
@Controller('athlete')
export class DocumentViewLinkController {
  constructor(
    private readonly views: DocumentViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Post('documents/:documentId/view-link')
  @HttpCode(HttpStatus.CREATED)
  async issueOwnLink(
    @Param() params: DocumentViewLinkParamsDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<DocumentViewLink | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await refuseViewLinkWhenOverLimit(this.rateLimit, actor.id, request, response);

    if (refusal !== null) return refusal;

    // No `staffVerified`: this route enforces neither StaffGate nor a step-up.
    return this.views.issueLink(actor, { documentId: params.documentId });
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }
}
