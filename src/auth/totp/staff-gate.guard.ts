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
import { SECOND_FACTOR_REQUIRED_CODE } from '../../common/errors/error-response';
import type { AuthenticatedRequest } from '../guards/auth.guard';
import { Role } from '../roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';

export const ALLOW_WITHOUT_SECOND_FACTOR_KEY = 'kfa:allowWithoutSecondFactor';

/**
 * Opens one route to a staff session that never proved a second factor.
 *
 * It is the narrow exception to the default-deny gate below: the second-factor
 * endpoints themselves need it, otherwise a staff account could not enrol, and
 * logout must stay reachable from any session.
 */
export const AllowWithoutSecondFactor = () => SetMetadata(ALLOW_WITHOUT_SECOND_FACTOR_KEY, true);

/** The one refusal the client can act on: the session has to prove itself. */
function deny(): never {
  throw new ForbiddenException({ code: SECOND_FACTOR_REQUIRED_CODE });
}

/**
 * Default-deny gate for staff sessions, between `AuthGuard` and `RolesGuard`.
 *
 * A USER or ATHLETE is untouched, and so is any public route: the gate exists
 * only because a staff account holds more than its password. It asks the session
 * row whether that session ever proved a second factor, and it asks about the
 * session named by the verified token, never one a caller names.
 *
 * Unlike `StepUpGuard` there is no window: once a session has proved the factor,
 * it stays usable until the session ends. A missing, foreign, revoked or expired
 * session, and an unreadable store, all read as "never proved": fail closed.
 *
 * Login is deliberately not the place for this check: asking for the code before
 * the phone proof would let anyone lock a staff account, and asking after it
 * would burn an SMS on every sign-in.
 */
@Injectable()
export class StaffGateGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const open = this.reflector.getAllAndOverride<boolean>(ALLOW_WITHOUT_SECOND_FACTOR_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (open === true) {
      return true;
    }

    // A public route has no principal to gate; `AuthGuard` decided it already.
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

    if (principal.role !== Role.ADMIN && principal.role !== Role.OWNER) {
      return true;
    }

    try {
      const stepupAt = await this.sessions.getStepUpAt(principal.sessionId, principal.userId);

      if (stepupAt === null) deny();

      return true;
    } catch {
      // An unreadable session has not proved anything.
      deny();
    }
  }
}
