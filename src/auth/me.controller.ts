import { Controller, Get, Req, Res, UnauthorizedException } from '@nestjs/common';
import type { Response } from 'express';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { AuthService, type SessionPrincipal } from './auth.service';
import { Authenticated } from './decorators/authenticated.decorator';
import type { AuthenticatedRequest } from './guards/auth.guard';
import { AllowWithoutSecondFactor } from './totp/staff-gate.guard';

/**
 * The four values a client needs to render itself after a login or a refresh.
 *
 * Nothing else may be added here: no phone, no id, no hash, no session or
 * device data, no timestamps. The access token already carries the identity;
 * this route only describes it.
 */
export interface MeResponseBody {
  readonly username: string;
  readonly role: 'USER' | 'ATHLETE' | 'ADMIN' | 'OWNER';
  readonly status: 'ACTIVE' | 'BLOCKED';
  readonly hasAthleteProfile: boolean;
}

/** The global guard already rejected anything without a trusted principal. */
function requirePrincipal(request: AuthenticatedRequest): SessionPrincipal {
  const auth = request.auth;

  if (auth === undefined) throw new UnauthorizedException();

  return { userId: auth.userId, sessionId: auth.sessionId };
}

/**
 * Read-only self-description behind a Bearer token.
 *
 * A separate controller on purpose: the rest of the auth surface is mounted
 * under `OriginCheckGuard` because it carries an ambient cookie, while this
 * route reads no cookie and changes nothing, so the CSRF check does not apply.
 *
 * `@AllowWithoutSecondFactor` keeps the route reachable for a staff session that
 * has not proved TOTP yet: the UI needs the answer to route that user to
 * enrolment instead of leaving it stuck on a 403 it cannot interpret.
 */
@Controller('auth')
export class MeController {
  constructor(private readonly auth: AuthService) {}

  @Authenticated()
  @AllowWithoutSecondFactor()
  @Get('me')
  async me(
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<MeResponseBody | ErrorResponseBody> {
    // The account id comes from the verified access token, never from the URL:
    // any query string is ignored by construction.
    const result = await this.auth.getMe(requirePrincipal(request));

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    if (result.outcome === 'unauthorized') {
      throw new UnauthorizedException();
    }

    return result.profile;
  }
}
