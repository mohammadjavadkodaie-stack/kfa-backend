/**
 * Roles skeleton - no authorisation logic is wired yet (metadata/decorators
 * and policies land with the auth task).
 */
export enum Role {
  USER = 'USER',
  ATHLETE = 'ATHLETE',
  ADMIN = 'ADMIN',
  OWNER = 'OWNER',
  IDENTITY_VERIFIER = 'IDENTITY_VERIFIER',
}

export const ALL_ROLES: readonly Role[] = Object.freeze(Object.values(Role));
