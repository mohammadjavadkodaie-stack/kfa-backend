import { Body, Controller, ForbiddenException, Get, Put, Req } from '@nestjs/common';
import { Authenticated } from '../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { getRequestId } from '../common/middleware/request-id.middleware';
import { AthleteService, type AthleteProfileView } from './athlete.service';
import { AthleteProfileDto, toProfileInput } from './dto/athlete-profile.dto';

/**
 * The caller's own athlete profile.
 *
 * Both routes carry `@Authenticated` and nothing else: every signed-in role may
 * keep a profile, and the role is never changed here. There is no id in the
 * path, the query or the body - the owner is the verified principal, so one
 * account cannot address another one's row.
 */
@Controller('athlete')
export class AthleteController {
  constructor(private readonly athlete: AthleteService) {}

  @Authenticated()
  @Get('profile')
  read(@Req() request: AuthenticatedRequest): Promise<AthleteProfileView> {
    return this.athlete.readProfile(this.actor(request), this.context(request));
  }

  /** Create or replace, decided by the repository's single-statement upsert. */
  @Authenticated()
  @Put('profile')
  save(
    @Body() body: AthleteProfileDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<AthleteProfileView> {
    return this.athlete.saveProfile(
      this.actor(request),
      toProfileInput(body),
      this.context(request),
    );
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }

  /** Request facts an audit row may carry; the service hashes the IP. */
  private context(request: AuthenticatedRequest): AccessPolicyContext {
    return { requestId: getRequestId(request), ip: request.ip ?? null };
  }
}
