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
import { Roles } from '../../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import { RequireStepUp } from '../../auth/totp/step-up.guard';
import type { ErrorResponseBody } from '../../common/errors/error-response';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentViewLinkParamsDto } from './document-view-link.dto';
import { DocumentViewService, type DocumentViewLink } from './document-view.service';
import { refuseViewLinkWhenOverLimit } from './view-link-limits';

/**
 * Issuing a single-use link to any account's document:
 * `POST /staff/documents/:documentId/view-link`.
 *
 * This is the only route that asserts `staffVerified`, and it may do so because
 * it is the only one that is gated for it:
 *
 * - `@Roles(ADMIN, OWNER)` keeps every USER and ATHLETE out;
 * - `StaffGateGuard` runs globally before the role check, so a staff session
 *   that never proved a second factor cannot reach this handler at all;
 * - `@RequireStepUp()` demands a step-up inside the five-minute window, so a
 *   session that proved the factor once this morning cannot read documents now.
 *
 * The link is still minted against fresh rows: a role change, a block or a
 * deletion between the step-up and the call is part of the decision, and every
 * refusal is the same generic 404 as the owner route - a staff caller learns
 * neither which documents exist nor who owns them.
 */
@Controller('staff/documents')
export class StaffDocumentViewLinkController {
  constructor(
    private readonly views: DocumentViewService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':documentId/view-link')
  @HttpCode(HttpStatus.CREATED)
  async issueLink(
    @Param() params: DocumentViewLinkParamsDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<DocumentViewLink | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await refuseViewLinkWhenOverLimit(this.rateLimit, actor.id, request, response);

    if (refusal !== null) return refusal;

    // The one place this assertion is made, and only after the guards above.
    return this.views.issueLink(actor, {
      documentId: params.documentId,
      staffVerified: true,
    });
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }
}
