import {
  ForbiddenException,
  Inject,
  Injectable,
  SetMetadata,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { STEP_UP_REQUIRED_CODE } from '../../common/errors/error-response';
import type { AuthenticatedRequest, RequestPrincipal } from '../guards/auth.guard';
import { Role } from '../roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';

/** A step-up is good for five minutes, then the session must prove itself again. */
export const STEPUP_WINDOW_MS = 300_000;

export const STEP_UP_REQUIRED_KEY = 'kfa:requireStepUp';

/**
 * Requires a fresh second factor on a sensitive action. Later admin endpoints
 * (stages 5, 8 and 10) put it on whatever changes access, accounts or the audit
 * trail, next to `@Roles(Role.ADMIN, Role.OWNER)`.
 */
export const RequireStepUp = () => SetMetadata(STEP_UP_REQUIRED_KEY, true);

/** The one refusal the client can act on: run a new step-up. */
function deny(): never {
  throw new ForbiddenException({ code: STEP_UP_REQUIRED_CODE });
}

/**
 * Second half of a sensitive route, after `AuthGuard` and `RolesGuard`.
 *
 * Both facts come from the verified token plus the session row, never from the
 * body or the headers: a caller cannot claim a step-up, and a stamp written on
 * one session does not open another.
 */
@Injectable()
export class StepUpGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required = this.reflector.getAllAndOverride<boolean>(STEP_UP_REQUIRED_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (required !== true) {
      return true;
    }

    // Nothing to protect on an explicitly public route.
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic === true) {
      return true;
    }

    const principal = context.switchToHttp().getRequest<AuthenticatedRequest>().auth;

    // AuthGuard runs first, so a missing principal is a wiring bug: deny anyway.
    if (principal === undefined) deny();

    if (!isStaff(principal)) deny();

    try {
      const stepupAt = await this.sessions.getStepUpAt(principal.sessionId, principal.userId);

      if (stepupAt === null) deny();

      const age = Date.now() - stepupAt.getTime();

      // A stamp from the future is not fresher than now, so it is refused too.
      if (age < 0 || age >= STEPUP_WINDOW_MS) deny();

      return true;
    } catch {
      // An unreadable session is not a fresh one.
      deny();
    }
  }
}

function isStaff(principal: RequestPrincipal): boolean {
  return principal.role === Role.ADMIN || principal.role === Role.OWNER;
}
