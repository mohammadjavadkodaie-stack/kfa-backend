import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'kfa:isPublic';

/**
 * Marks a route (or controller) as reachable without authentication.
 * Everything else is denied by default (see AuthGuard).
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
