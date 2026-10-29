import {
  ForbiddenException,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../decorators/roles.decorator';
import type { Role } from '../roles';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Second half of the default-deny pair. It runs after `AuthGuard`, which has
 * already populated `request.auth` from the database.
 *
 * A route without `@Roles`/`@RequireVerifier` keeps today's behaviour: any
 * authenticated user. A marked route answers one generic 403 when the principal
 * does not match, so the response reveals neither the allowed roles nor the
 * caller's own role or verifier flag.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic === true) {
      return true;
    }

    const roles = this.reflector.getAllAndOverride<readonly Role[] | undefined>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const verifierRequired =
      this.reflector.getAllAndOverride<boolean>(REQUIRES_IDENTITY_VERIFIER_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) === true;

    if (roles === undefined && !verifierRequired) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const principal = request.auth;

    // AuthGuard runs first globally, so a missing principal is a wiring bug.
    // Deny anyway rather than treating the request as privileged.
    if (principal === undefined) {
      throw new ForbiddenException();
    }

    if (roles !== undefined && !roles.includes(principal.role)) {
      throw new ForbiddenException();
    }

    if (verifierRequired && !principal.identityVerifier) {
      throw new ForbiddenException();
    }

    return true;
  }
}
