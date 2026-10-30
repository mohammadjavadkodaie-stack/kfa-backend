/**
 * Assignable account roles.
 *
 * The identity verifier is deliberately not a role: `users.identity_verifier`
 * is a separate permission that can be granted to any role and is required with
 * `@RequireVerifier()`. Neither the role nor the flag is ever read from the
 * access token; the guard loads both from the database on every request.
 */
export enum Role {
  USER = 'USER',
  ATHLETE = 'ATHLETE',
  ADMIN = 'ADMIN',
  OWNER = 'OWNER',
}

export const ALL_ROLES: readonly Role[] = Object.freeze(Object.values(Role));

/** Narrows a value read from storage; an unknown role is refused, not guessed. */
export function parseRole(value: string): Role | null {
  return ALL_ROLES.find((role) => String(role) === value) ?? null;
}

/** The roles that get the shorter session policy. */
export function isStaffRole(role: Role): boolean {
  return role === Role.ADMIN || role === Role.OWNER;
}
