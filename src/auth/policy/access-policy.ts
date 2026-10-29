import { parseRole, Role } from '../roles';

/**
 * Every administrative action the application may perform on an account.
 *
 * The list is closed: an action that is not named here is refused, so a new
 * endpoint cannot become reachable by inventing a string. `user.change_role`
 * carries the requested new role in the request (see `AccessRequest`).
 */
export enum AccessAction {
  USER_BLOCK = 'user.block',
  USER_UNBLOCK = 'user.unblock',
  USER_DELETE = 'user.delete',
  USER_CHANGE_ROLE = 'user.change_role',
  ADMIN_GRANT = 'admin.grant',
  ADMIN_REVOKE = 'admin.revoke',
  OWNER_GRANT = 'owner.grant',
}

export const ALL_ACCESS_ACTIONS: readonly AccessAction[] = Object.freeze(
  Object.values(AccessAction),
);

/** Narrows a value read from a request; an unknown action is refused, not guessed. */
export function parseAccessAction(value: string): AccessAction | null {
  return ALL_ACCESS_ACTIONS.find((action) => String(action) === value) ?? null;
}

/**
 * One side of a decision: the caller or the account being acted on. The role is
 * whatever storage reported for this request - it is re-parsed here and never
 * taken from a token or a body.
 */
export interface PolicySubject {
  readonly id: string;
  readonly role: Role;
}

/**
 * What the caller is asking for. `role` is read by `user.change_role` only and
 * ignored by every other action.
 */
export interface AccessRequest {
  readonly action: string;
  readonly role?: string | null;
}

/**
 * Internal denial codes. They exist for logs and tests only and are never sent
 * to the client: the response is always the same generic 403.
 */
export type DenialReason =
  | 'unknown_actor_role'
  | 'unknown_target_role'
  | 'unknown_action'
  | 'actor_not_permitted'
  | 'self_action'
  | 'target_is_owner'
  | 'owner_grant_forbidden'
  | 'unknown_requested_role'
  | 'target_already_in_role'
  | 'target_already_admin'
  | 'target_not_admin'
  | 'admin_management_requires_owner'
  | 'admin_delete_forbidden'
  | 'admin_target_not_permitted';

export type PolicyDecision =
  { readonly allowed: true } | { readonly allowed: false; readonly reason: DenialReason };

function allow(): PolicyDecision {
  return { allowed: true };
}

function deny(reason: DenialReason): PolicyDecision {
  return { allowed: false, reason };
}

/**
 * Decides one administrative action. Pure: no I/O, no Nest, no clock, so the
 * whole rule set is testable as a table.
 *
 * Deny is the default everywhere - an unknown role, an unknown action and an
 * action that no rule grants are all refused.
 */
export function decide(
  actor: PolicySubject,
  request: AccessRequest,
  target: PolicySubject,
): PolicyDecision {
  const actorRole = parseRole(String(actor.role));

  if (actorRole === null) return deny('unknown_actor_role');

  const targetRole = parseRole(String(target.role));

  if (targetRole === null) return deny('unknown_target_role');

  const action = parseAccessAction(String(request.action));

  if (action === null) return deny('unknown_action');

  // These actions belong to staff. Checking this before the remaining rules
  // keeps the answer for a USER/ATHLETE actor the same whatever the target is.
  if (actorRole !== Role.ADMIN && actorRole !== Role.OWNER) return deny('actor_not_permitted');

  // No action on oneself, for every role and every action: an owner does not
  // block, demote or delete their own account through the API either.
  if (actor.id === target.id) return deny('self_action');

  // The owner account is outside the application: nobody may block, unblock,
  // demote, change the role of or delete it, and that includes the owner.
  if (targetRole === Role.OWNER) return deny('target_is_owner');

  switch (action) {
    case AccessAction.OWNER_GRANT:
      // Ownership is never granted through the application, not even by the
      // owner: it is a deployment decision, not a runtime one.
      return deny('owner_grant_forbidden');
    case AccessAction.USER_BLOCK:
    case AccessAction.USER_UNBLOCK:
    case AccessAction.USER_DELETE:
      return decideAccountAction(actorRole, action, targetRole);
    case AccessAction.USER_CHANGE_ROLE:
      return decideRoleChange(actorRole, request.role, targetRole);
    case AccessAction.ADMIN_GRANT:
      return decideAdminGrant(actorRole, targetRole);
    case AccessAction.ADMIN_REVOKE:
      return decideAdminRevoke(actorRole, targetRole);
  }
}

/**
 * Block, unblock and delete. The owner target is already refused above, so the
 * target here is a regular account, an athlete or an admin.
 */
function decideAccountAction(
  actorRole: Role,
  action: AccessAction,
  targetRole: Role,
): PolicyDecision {
  if (actorRole === Role.OWNER) return allow();

  // An admin moderates ordinary accounts only. Refusing a peer admin is a
  // conservative choice: staff disputes are the owner's business.
  if (action === AccessAction.USER_DELETE) return deny('admin_delete_forbidden');

  return targetRole === Role.USER || targetRole === Role.ATHLETE
    ? allow()
    : deny('admin_target_not_permitted');
}

function decideRoleChange(
  actorRole: Role,
  requested: string | null | undefined,
  targetRole: Role,
): PolicyDecision {
  // Changing anyone's role is owner-only; an admin never promotes anybody, not
  // even a regular user to admin.
  if (actorRole !== Role.OWNER) return deny('admin_management_requires_owner');

  const requestedRole = requested === undefined || requested === null ? null : parseRole(requested);

  if (requestedRole === null) return deny('unknown_requested_role');
  if (requestedRole === Role.OWNER) return deny('owner_grant_forbidden');

  // A no-op transition has no legitimate use; refusing it keeps the audit trail
  // free of privilege changes that did not happen.
  if (requestedRole === targetRole) return deny('target_already_in_role');

  return allow();
}

function decideAdminGrant(actorRole: Role, targetRole: Role): PolicyDecision {
  if (actorRole !== Role.OWNER) return deny('admin_management_requires_owner');

  return targetRole === Role.ADMIN ? deny('target_already_admin') : allow();
}

function decideAdminRevoke(actorRole: Role, targetRole: Role): PolicyDecision {
  if (actorRole !== Role.OWNER) return deny('admin_management_requires_owner');

  return targetRole === Role.ADMIN ? allow() : deny('target_not_admin');
}
