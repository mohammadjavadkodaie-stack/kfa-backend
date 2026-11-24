import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import type { ErrorResponseBody } from '../common/errors/error-response';
import { getRequestId } from '../common/middleware/request-id.middleware';
import { refuseWhenOverLimit } from '../documents/view/view-link-limits';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import {
  parseCreateCompetitionResult,
  parseUpdateCompetitionResult,
  RankingResultParamsDto,
  RankingResultQueryDto,
} from './ranking.dto';
import { RANKING_WRITE_LIMITS, RANKING_WRITE_RATE_LIMIT_SCOPE } from './ranking-limits';
import {
  RankingService,
  type CompetitionResultPage,
  type CompetitionResultView,
} from './ranking.service';

/**
 * Staff entry and correction of competition results:
 * `POST /staff/ranking/results`, `PATCH /staff/ranking/results/:id`,
 * `DELETE /staff/ranking/results/:id` and `GET /staff/ranking/results`.
 *
 * The guard stack is the staff write stack:
 *
 * - the global `AuthGuard` resolves the caller;
 * - the global `StaffGateGuard` keeps a staff session that never proved a second
 *   factor out of the whole controller;
 * - `@Roles(ADMIN, OWNER)` keeps every USER and ATHLETE out of every route, so
 *   no athlete can write a score - there is no athlete-facing route at all;
 * - `@RequireStepUp()` additionally covers all three writes.
 *
 * The read returns stored results only; no rank is computed or exposed yet.
 * Every write is counted per user after the input is parsed, so a malformed body
 * or id costs no budget.
 */
@Controller('staff/ranking')
export class StaffRankingController {
  constructor(
    private readonly ranking: RankingService,
    private readonly rateLimit: RateLimitService,
  ) {}

  /** One page of stored results, newest event first; an empty page has no cursor. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get('results')
  async list(@Query() query: RankingResultQueryDto): Promise<CompetitionResultPage> {
    return this.ranking.listResults(query);
  }

  /** Records a staff-entered result for an approved athlete. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post('results')
  async create(
    // zod is the whole gate, so the global pipe skips the untyped body.
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<CompetitionResultView | ErrorResponseBody> {
    const input = parseCreateCompetitionResult(body);
    const actor = this.actor(request);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    return this.ranking.createResult(actor, input, this.context(request));
  }

  /** Corrects points, event name or date; the ranking is recomputed server-side. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Patch('results/:id')
  async update(
    @Param() params: RankingResultParamsDto,
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<CompetitionResultView | ErrorResponseBody> {
    const input = parseUpdateCompetitionResult(body);
    const actor = this.actor(request);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    return this.ranking.updateResult(actor, params.id, input, this.context(request));
  }

  /** Withdraws one result; the ranking is recomputed in the same transaction. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Delete('results/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param() params: RankingResultParamsDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void | ErrorResponseBody> {
    const actor = this.actor(request);

    const refusal = await this.refuseWhenOverLimit(actor.id, request, response);

    if (refusal !== null) return refusal;

    await this.ranking.deleteResult(actor, params.id, this.context(request));
  }

  /** the shared per-user write budget; the first refusal wins. */
  private async refuseWhenOverLimit(
    userId: string,
    request: AuthenticatedRequest,
    response: Response,
  ): Promise<ErrorResponseBody | null> {
    return refuseWhenOverLimit(
      this.rateLimit,
      RANKING_WRITE_RATE_LIMIT_SCOPE,
      RANKING_WRITE_LIMITS,
      userId,
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

  /** Request facts an audit row may carry; the service hashes the IP. */
  private context(request: AuthenticatedRequest) {
    return { requestId: getRequestId(request), ip: request.ip ?? null };
  }
}
