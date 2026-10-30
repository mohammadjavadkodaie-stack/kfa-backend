import {
  ForbiddenException,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { AUTHENTICATED_KEY } from '../decorators/authenticated.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../decorators/roles.decorator';
import type { Role } from '../roles';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Second half of the default-deny pair. It runs after `AuthGuard`, which has
 * already populated `request.auth` from the database.
 *
 * Every non-public route has to carry one marker: `@Roles(...)`,
 * `@RequireVerifier` or `@Authenticated`. None of them means the route was never
 * meant to be reachable, so it is refused instead of opened to every user. A
 * refusal is always the same generic 403, so the response reveals neither the
 * allowed roles nor the caller's own role or verifier flag.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()];

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets);

    if (isPublic === true) {
      return true;
    }

    const roles = this.reflector.getAllAndOverride<readonly Role[] | undefined>(ROLES_KEY, targets);
    const verifierRequired =
      this.reflector.getAllAndOverride<boolean>(REQUIRES_IDENTITY_VERIFIER_KEY, targets) === true;
    const authenticated =
      this.reflector.getAllAndOverride<boolean>(AUTHENTICATED_KEY, targets) === true;

    // Metadata that is not a list of roles cannot grant anything: deny.
    if (roles !== undefined && !Array.isArray(roles)) {
      throw new ForbiddenException();
    }

    if (roles === undefined && !verifierRequired && !authenticated) {
      throw new ForbiddenException();
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const principal = request.auth;

    // AuthGuard runs first globally, so a missing principal is a wiring bug.
    // Deny anyway rather than treating the request as privileged.
    if (principal === undefined || principal === null) {
      throw new ForbiddenException();
    }

    // @Authenticated admits any role, so @Roles stays the stricter rule when
    // both are present.
    if (roles !== undefined && !roles.includes(principal.role)) {
      throw new ForbiddenException();
    }

    if (verifierRequired && !principal.identityVerifier) {
      throw new ForbiddenException();
    }

    return true;
  }
}
