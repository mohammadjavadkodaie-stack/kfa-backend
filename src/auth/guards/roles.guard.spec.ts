import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { AUTHENTICATED_KEY } from '../decorators/authenticated.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../roles';
import type { AuthenticatedRequest, RequestPrincipal } from './auth.guard';
import { RolesGuard } from './roles.guard';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';

const handler = (): void => undefined;
class TestController {}

interface Metadata {
  readonly isPublic?: boolean;
  readonly roles?: readonly Role[];
  readonly requiresVerifier?: boolean;
  readonly authenticated?: boolean;
}

function principal(role: Role, identityVerifier = false): RequestPrincipal {
  return {
    userId: USER_ID,
    sessionId: SESSION_ID,
    role,
    identityVerifier,
    expiresAtSeconds: 1_700_000_000,
  };
}

/**
 * Builds the guard with a stubbed `Reflector`, so the metadata a real decorator
 * would set is stated explicitly in each test.
 */
function createHarness(metadata: Metadata, authenticated?: RequestPrincipal) {
  const request = { headers: {} } as unknown as AuthenticatedRequest;

  if (authenticated !== undefined) {
    request.auth = authenticated;
  }

  const context = {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;

  const getAllAndOverride = jest.fn((key: string, _targets: unknown[]) => {
    switch (key) {
      case IS_PUBLIC_KEY:
        return metadata.isPublic;
      case ROLES_KEY:
        return metadata.roles;
      case REQUIRES_IDENTITY_VERIFIER_KEY:
        return metadata.requiresVerifier;
      case AUTHENTICATED_KEY:
        return metadata.authenticated;
      default:
        return undefined;
    }
  });

  return {
    guard: new RolesGuard({ getAllAndOverride } as unknown as Reflector),
    context,
    request,
  };
}

function allowed(metadata: Metadata, authenticated: RequestPrincipal): boolean {
  const { guard, context } = createHarness(metadata, authenticated);

  return guard.canActivate(context);
}

function denied(metadata: Metadata, authenticated?: RequestPrincipal): void {
  const { guard, context } = createHarness(metadata, authenticated);

  expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
}

describe('RolesGuard', () => {
  it.each([Role.USER, Role.ATHLETE, Role.ADMIN, Role.OWNER])(
    'refuses %s on a non-public route with no marker',
    (role) => {
      denied({}, principal(role));
    },
  );

  it('does nothing for @Public routes, even without a principal', () => {
    expect(allowed({ isPublic: true }, principal(Role.USER))).toBe(true);

    const { guard, context } = createHarness({ isPublic: true, roles: [Role.ADMIN] });

    expect(guard.canActivate(context)).toBe(true);
  });

  it('admits every role on an @Authenticated route', () => {
    for (const role of Object.values(Role)) {
      expect(allowed({ authenticated: true }, principal(role))).toBe(true);
    }
  });

  it('lets @Roles win when @Authenticated is there too', () => {
    const metadata: Metadata = { roles: [Role.ADMIN], authenticated: true };

    expect(allowed(metadata, principal(Role.ADMIN))).toBe(true);
    denied(metadata, principal(Role.USER));
    denied(metadata, principal(Role.OWNER));
  });

  it('fails closed when the marker metadata is unusable', () => {
    const { context } = createHarness({}, principal(Role.ADMIN));
    // Only a hand-written reflector can produce this; it must not read as "open".
    const guard = new RolesGuard({
      getAllAndOverride: (key: string) => (key === ROLES_KEY ? 'ADMIN' : undefined),
    } as unknown as Reflector);

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('lets a listed role through', () => {
    expect(allowed({ roles: [Role.ADMIN] }, principal(Role.ADMIN))).toBe(true);
    expect(allowed({ roles: [Role.ADMIN, Role.OWNER] }, principal(Role.OWNER))).toBe(true);
    expect(allowed({ roles: [Role.ADMIN, Role.OWNER] }, principal(Role.ADMIN))).toBe(true);
  });

  it.each([Role.USER, Role.ATHLETE])('refuses %s on a route for another role', (role) => {
    denied({ roles: [Role.ADMIN] }, principal(role));
    denied({ roles: [Role.ADMIN, Role.OWNER] }, principal(role));
  });

  it('refuses an OWNER on an ADMIN-only route', () => {
    denied({ roles: [Role.ADMIN] }, principal(Role.OWNER));
  });

  it('requires the verifier permission, independently of the role', () => {
    expect(allowed({ requiresVerifier: true }, principal(Role.USER, true))).toBe(true);

    for (const role of Object.values(Role)) {
      denied({ requiresVerifier: true }, principal(role, false));
    }
  });

  it('checks the role and the verifier flag together when both are required', () => {
    const metadata: Metadata = { roles: [Role.ADMIN], requiresVerifier: true };

    expect(allowed(metadata, principal(Role.ADMIN, true))).toBe(true);
    denied(metadata, principal(Role.ADMIN, false));
    denied(metadata, principal(Role.USER, true));
  });

  it('fails closed when a protected route has no principal', () => {
    denied({ roles: [Role.ADMIN] });
    denied({ requiresVerifier: true });
    denied({ authenticated: true });
    denied({});
  });

  it('refuses everyone when @Roles() lists no role', () => {
    for (const role of Object.values(Role)) {
      denied({ roles: [] }, principal(role));
    }
  });
});
