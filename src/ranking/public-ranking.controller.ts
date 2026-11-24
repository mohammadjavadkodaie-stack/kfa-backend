import { Controller, Get, Param, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { refuseWhenOverLimit } from '../documents/view/view-link-limits';
import { Public } from '../common/decorators/public.decorator';
import type { ErrorResponseBody } from '../common/errors/error-response';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import { parsePublicRankingProfileId, parsePublicRankingQuery } from './public-ranking.dto';
import {
  PUBLIC_RANKING_CACHE_SECONDS,
  PublicRankingService,
  type PublicRankingItem,
  type PublicRankingPage,
} from './public-ranking.service';
import {
  PUBLIC_RANKING_LIST_LIMITS,
  PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE,
  PUBLIC_RANKING_READ_LIMITS,
  PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE,
} from './ranking-limits';

/**
 * The unauthenticated leaderboard, read only:
 *
 * - `GET /public/ranking?limit=&cursor=` returns one page of approved athletes;
 * - `GET /public/ranking/:athleteProfileId` returns one athlete's rank.
 *
 * Both routes are marked `@Public()` explicitly: the guard's default is deny, so
 * nothing becomes reachable by accident. Neither takes a caller identity, so
 * both spend a per-address budget, and both are parsed and validated before a
 * counter is charged.
 *
 * The approval check runs at read time in the repository predicate, so a profile
 * that was un-approved disappears at once even if its ranking row is stale. Every
 * entry is the profile id plus the two derived numbers - no user id, no email,
 * no entered-by account, no individual result.
 */
@Controller('public/ranking')
export class PublicRankingController {
  constructor(
    private readonly ranking: PublicRankingService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Public()
  @Get()
  async list(
    @Query() query: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PublicRankingPage | ErrorResponseBody> {
    // Parsed first: a malformed or unknown query key is a 400 and costs no budget.
    const page = parsePublicRankingQuery(query);

    const refusal = await this.refuse(
      PUBLIC_RANKING_LIST_RATE_LIMIT_SCOPE,
      PUBLIC_RANKING_LIST_LIMITS,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    // Set only after the limiter agreed: a 429 must never become publicly cacheable.
    this.harden(response);

    return this.ranking.list(page);
  }

  @Public()
  @Get(':athleteProfileId')
  async read(
    @Param('athleteProfileId') athleteProfileId: string,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PublicRankingItem | ErrorResponseBody> {
    const profileId = parsePublicRankingProfileId(athleteProfileId);

    const refusal = await this.refuse(
      PUBLIC_RANKING_READ_RATE_LIMIT_SCOPE,
      PUBLIC_RANKING_READ_LIMITS,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    this.harden(response);

    return this.ranking.read(profileId);
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
   * The headers every successful answer carries. A short lifetime allows a CDN
   * to absorb a crowd while an approval withdrawal still takes effect quickly;
   * `nosniff` keeps the browser from second-guessing the declared JSON type.
   */
  private harden(response: Response): void {
    response.setHeader('Cache-Control', `public, max-age=${PUBLIC_RANKING_CACHE_SECONDS}`);
    response.setHeader('X-Content-Type-Options', 'nosniff');
  }

  /** The resolved client address, already unwrapped by the trusted proxy setup. */
  private address(request: Request): string {
    return request.ip ?? request.socket?.remoteAddress ?? 'unknown';
  }
}
