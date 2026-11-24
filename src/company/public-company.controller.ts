import { Controller, Get, Param, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import type { ErrorResponseBody } from '../common/errors/error-response';
import { refuseWhenOverLimit } from '../documents/view/view-link-limits';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import { parsePublicCompanyQuery } from './public-company.dto';
import {
  PUBLIC_COMPANY_LIST_LIMITS,
  PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE,
  PUBLIC_COMPANY_READ_LIMITS,
  PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE,
} from './public-company-limits';
import {
  PUBLIC_COMPANY_CACHE_SECONDS,
  PublicCompanyService,
  type PublicCompanyItem,
  type PublicCompanyPage,
} from './public-company.service';

/**
 * The unauthenticated company directory, read only:
 *
 * - `GET /public/companies?limit=&cursor=&kind=` returns one page by slug;
 * - `GET /public/companies/:slug` returns one company card.
 *
 * Both routes are marked `@Public()` explicitly: the guard's default is deny, so
 * nothing becomes reachable by accident. Neither takes a caller identity, so
 * both spend a per-address budget, and both are parsed before a counter is
 * charged. The single read deliberately does not parse its path segment - a
 * malformed slug is the same 404 as a missing one, so the route cannot be used
 * to enumerate what exists.
 */
@Controller('public/companies')
export class PublicCompanyController {
  constructor(
    private readonly companies: PublicCompanyService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Public()
  @Get()
  async list(
    @Query() query: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PublicCompanyPage | ErrorResponseBody> {
    // Parsed first: a malformed or unknown query key is a 400 and costs no budget.
    const page = parsePublicCompanyQuery(query);

    const refusal = await this.refuse(
      PUBLIC_COMPANY_LIST_RATE_LIMIT_SCOPE,
      PUBLIC_COMPANY_LIST_LIMITS,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    // Set only after the limiter agreed: a 429 must never become publicly cacheable.
    this.harden(response);

    return this.companies.list(page);
  }

  @Public()
  @Get(':slug')
  async read(
    @Param('slug') slug: string,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PublicCompanyItem | ErrorResponseBody> {
    const refusal = await this.refuse(
      PUBLIC_COMPANY_READ_RATE_LIMIT_SCOPE,
      PUBLIC_COMPANY_READ_LIMITS,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    this.harden(response);

    return this.companies.read(slug);
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
   * to absorb a crowd while a correction or a retirement still takes effect
   * quickly; `nosniff` keeps the browser from second-guessing the declared JSON
   * type.
   */
  private harden(response: Response): void {
    response.setHeader('Cache-Control', `public, max-age=${PUBLIC_COMPANY_CACHE_SECONDS}`);
    response.setHeader('X-Content-Type-Options', 'nosniff');
  }

  /** The resolved client address, already unwrapped by the trusted proxy setup. */
  private address(request: Request): string {
    return request.ip ?? request.socket?.remoteAddress ?? 'unknown';
  }
}
