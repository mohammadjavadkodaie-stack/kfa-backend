import { SetMetadata } from '@nestjs/common';

export const AUTHENTICATED_KEY = 'kfa:authenticated';

/**
 * Marks a route as reachable by every signed-in role.
 *
 * It exists so a non-public route states its intent: `RolesGuard` refuses a
 * route that carries none of `@Roles`, `@RequireVerifier` or this marker, so a
 * forgotten decorator closes a route instead of opening it to all users.
 */
export const Authenticated = () => SetMetadata(AUTHENTICATED_KEY, true);
