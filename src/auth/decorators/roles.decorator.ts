import { SetMetadata } from '@nestjs/common';
import type { Role } from '../roles';

export const ROLES_KEY = 'kfa:roles';
export const REQUIRES_IDENTITY_VERIFIER_KEY = 'kfa:requiresIdentityVerifier';

/**
 * Requires one of `roles`. A route without it is unchanged: any authenticated
 * user. Checked by `RolesGuard`, which runs after `AuthGuard`.
 */
export const Roles = (...roles: readonly Role[]) => SetMetadata(ROLES_KEY, roles);

/**
 * Requires the identity-verifier permission. It is not a role: the flag lives
 * on the user and can be held by any role.
 */
export const RequireVerifier = () => SetMetadata(REQUIRES_IDENTITY_VERIFIER_KEY, true);
