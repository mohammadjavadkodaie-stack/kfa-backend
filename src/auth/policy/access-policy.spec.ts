import { ALL_ROLES, Role } from '../roles';
import {
  ALL_ACCESS_ACTIONS,
  AccessAction,
  decide,
  type AccessRequest,
  type PolicySubject,
} from './access-policy';

const ACTOR_ID = '11111111-1111-4111-8111-111111111111';
const TARGET_ID = '22222222-2222-4222-8222-222222222222';

function actorOf(role: Role): PolicySubject {
  return { id: ACTOR_ID, role };
}

function targetOf(role: Role): PolicySubject {
  return { id: TARGET_ID, role };
}

function request(action: AccessAction, role?: Role): AccessRequest {
  return role === undefined ? { action } : { action, role };
}

interface PairRules {
  readonly actor: Role;
  readonly target: Role;
  /** The complete list of actions this pair may perform; everything else is refused. */
  readonly allowed: readonly AccessAction[];
  /** Requested role used for `user.change_role` in the grid below. */
  readonly changeTo: Role;
}

/**
 * Hand-written expectation table. The allow/deny answer is written out here, not
 * derived from the implementation, so a change in the rules shows up as a
 * failure in this table instead of being silently accepted.
 */
const MATRIX: readonly PairRules[] = [
  // A USER actor has no administrative action at all, whoever the target is.
  { actor: Role.USER, target: Role.USER, allowed: [], changeTo: Role.ATHLETE },
  { actor: Role.USER, target: Role.ATHLETE, allowed: [], changeTo: Role.ADMIN },
  { actor: Role.USER, target: Role.ADMIN, allowed: [], changeTo: Role.USER },
  { actor: Role.USER, target: Role.OWNER, allowed: [], changeTo: Role.USER },
  // An ATHLETE actor is in exactly the same position.
  { actor: Role.ATHLETE, target: Role.USER, allowed: [], changeTo: Role.ADMIN },
  { actor: Role.ATHLETE, target: Role.ATHLETE, allowed: [], changeTo: Role.USER },
  { actor: Role.ATHLETE, target: Role.ADMIN, allowed: [], changeTo: Role.USER },
  { actor: Role.ATHLETE, target: Role.OWNER, allowed: [], changeTo: Role.USER },
  // An ADMIN blocks and unblocks ordinary accounts and nothing else: no delete,
  // no role change, no grant or revoke, and no action on a peer admin.
  {
    actor: Role.ADMIN,
    target: Role.USER,
    allowed: [AccessAction.USER_BLOCK, AccessAction.USER_UNBLOCK],
    changeTo: Role.ATHLETE,
  },
  {
    actor: Role.ADMIN,
    target: Role.ATHLETE,
    allowed: [AccessAction.USER_BLOCK, AccessAction.USER_UNBLOCK],
    changeTo: Role.USER,
  },
  { actor: Role.ADMIN, target: Role.ADMIN, allowed: [], changeTo: Role.USER },
  { actor: Role.ADMIN, target: Role.OWNER, allowed: [], changeTo: Role.USER },
  // The OWNER may do everything to regular accounts and athletes, and may
  // moderate and demote an admin - but never grant or revoke ownership. There is
  // only one owner account, so no action targets another owner.
  {
    actor: Role.OWNER,
    target: Role.USER,
    allowed: [
      AccessAction.USER_BLOCK,
      AccessAction.USER_UNBLOCK,
      AccessAction.USER_DELETE,
      AccessAction.USER_CHANGE_ROLE,
      AccessAction.ADMIN_GRANT,
    ],
    changeTo: Role.ATHLETE,
  },
  {
    actor: Role.OWNER,
    target: Role.ATHLETE,
    allowed: [
      AccessAction.USER_BLOCK,
      AccessAction.USER_UNBLOCK,
      AccessAction.USER_DELETE,
      AccessAction.USER_CHANGE_ROLE,
      AccessAction.ADMIN_GRANT,
    ],
    changeTo: Role.ADMIN,
  },
  {
    actor: Role.OWNER,
    target: Role.ADMIN,
    allowed: [
      AccessAction.USER_BLOCK,
      AccessAction.USER_UNBLOCK,
      AccessAction.USER_DELETE,
      AccessAction.USER_CHANGE_ROLE,
      AccessAction.ADMIN_REVOKE,
    ],
    changeTo: Role.USER,
  },
  { actor: Role.OWNER, target: Role.OWNER, allowed: [], changeTo: Role.USER },
];

describe('decide: the full role/action matrix', () => {
  for (const pair of MATRIX) {
    for (const action of ALL_ACCESS_ACTIONS) {
      const expected = pair.allowed.includes(action);
      const request =
        action === AccessAction.USER_CHANGE_ROLE ? { action, role: pair.changeTo } : { action };

      it(`${expected ? 'allows' : 'refuses'} ${pair.actor} -> ${pair.target} ${action}`, () => {
        expect(decide(actorOf(pair.actor), request, targetOf(pair.target)).allowed).toBe(expected);
      });
    }
  }
});

/** [actor role, target role, requested role, allowed] - written out by hand. */
const ROLE_CHANGES: readonly (readonly [Role, Role, Role, boolean])[] = [
  // A USER actor never renames a role.
  [Role.USER, Role.USER, Role.USER, false],
  [Role.USER, Role.USER, Role.ATHLETE, false],
  [Role.USER, Role.USER, Role.ADMIN, false],
  [Role.USER, Role.USER, Role.OWNER, false],
  [Role.USER, Role.ATHLETE, Role.USER, false],
  [Role.USER, Role.ATHLETE, Role.ATHLETE, false],
  [Role.USER, Role.ATHLETE, Role.ADMIN, false],
  [Role.USER, Role.ATHLETE, Role.OWNER, false],
  [Role.USER, Role.ADMIN, Role.USER, false],
  [Role.USER, Role.ADMIN, Role.ATHLETE, false],
  [Role.USER, Role.ADMIN, Role.ADMIN, false],
  [Role.USER, Role.ADMIN, Role.OWNER, false],
  [Role.USER, Role.OWNER, Role.USER, false],
  [Role.USER, Role.OWNER, Role.ATHLETE, false],
  [Role.USER, Role.OWNER, Role.ADMIN, false],
  [Role.USER, Role.OWNER, Role.OWNER, false],
  // Neither does an ATHLETE.
  [Role.ATHLETE, Role.USER, Role.USER, false],
  [Role.ATHLETE, Role.USER, Role.ATHLETE, false],
  [Role.ATHLETE, Role.USER, Role.ADMIN, false],
  [Role.ATHLETE, Role.USER, Role.OWNER, false],
  [Role.ATHLETE, Role.ATHLETE, Role.USER, false],
  [Role.ATHLETE, Role.ATHLETE, Role.ATHLETE, false],
  [Role.ATHLETE, Role.ATHLETE, Role.ADMIN, false],
  [Role.ATHLETE, Role.ATHLETE, Role.OWNER, false],
  [Role.ATHLETE, Role.ADMIN, Role.USER, false],
  [Role.ATHLETE, Role.ADMIN, Role.ATHLETE, false],
  [Role.ATHLETE, Role.ADMIN, Role.ADMIN, false],
  [Role.ATHLETE, Role.ADMIN, Role.OWNER, false],
  [Role.ATHLETE, Role.OWNER, Role.USER, false],
  [Role.ATHLETE, Role.OWNER, Role.ATHLETE, false],
  [Role.ATHLETE, Role.OWNER, Role.ADMIN, false],
  [Role.ATHLETE, Role.OWNER, Role.OWNER, false],
  // An ADMIN cannot change anyone's role, not even their own or a regular user's.
  [Role.ADMIN, Role.USER, Role.USER, false],
  [Role.ADMIN, Role.USER, Role.ATHLETE, false],
  [Role.ADMIN, Role.USER, Role.ADMIN, false],
  [Role.ADMIN, Role.USER, Role.OWNER, false],
  [Role.ADMIN, Role.ATHLETE, Role.USER, false],
  [Role.ADMIN, Role.ATHLETE, Role.ATHLETE, false],
  [Role.ADMIN, Role.ATHLETE, Role.ADMIN, false],
  [Role.ADMIN, Role.ATHLETE, Role.OWNER, false],
  [Role.ADMIN, Role.ADMIN, Role.USER, false],
  [Role.ADMIN, Role.ADMIN, Role.ATHLETE, false],
  [Role.ADMIN, Role.ADMIN, Role.ADMIN, false],
  [Role.ADMIN, Role.ADMIN, Role.OWNER, false],
  [Role.ADMIN, Role.OWNER, Role.USER, false],
  [Role.ADMIN, Role.OWNER, Role.ATHLETE, false],
  [Role.ADMIN, Role.OWNER, Role.ADMIN, false],
  [Role.ADMIN, Role.OWNER, Role.OWNER, false],
  // The OWNER promotes and demotes regular accounts, athletes and admins, but
  // never to OWNER and never as a no-op.
  [Role.OWNER, Role.USER, Role.USER, false],
  [Role.OWNER, Role.USER, Role.ATHLETE, true],
  [Role.OWNER, Role.USER, Role.ADMIN, true],
  [Role.OWNER, Role.USER, Role.OWNER, false],
  [Role.OWNER, Role.ATHLETE, Role.USER, true],
  [Role.OWNER, Role.ATHLETE, Role.ATHLETE, false],
  [Role.OWNER, Role.ATHLETE, Role.ADMIN, true],
  [Role.OWNER, Role.ATHLETE, Role.OWNER, false],
  [Role.OWNER, Role.ADMIN, Role.USER, true],
  [Role.OWNER, Role.ADMIN, Role.ATHLETE, true],
  [Role.OWNER, Role.ADMIN, Role.ADMIN, false],
  [Role.OWNER, Role.ADMIN, Role.OWNER, false],
  // The owner account is never touched, and ownership is never handed out.
  [Role.OWNER, Role.OWNER, Role.USER, false],
  [Role.OWNER, Role.OWNER, Role.ATHLETE, false],
  [Role.OWNER, Role.OWNER, Role.ADMIN, false],
  [Role.OWNER, Role.OWNER, Role.OWNER, false],
];

describe('decide: every requested role for user.change_role', () => {
  for (const [actorRole, targetRole, requestedRole, allowed] of ROLE_CHANGES) {
    it(`${allowed ? 'allows' : 'refuses'} ${actorRole} changing ${targetRole} to ${requestedRole}`, () => {
      const decision = decide(
        actorOf(actorRole),
        { action: AccessAction.USER_CHANGE_ROLE, role: requestedRole },
        targetOf(targetRole),
      );

      expect(decision.allowed).toBe(allowed);
    });
  }
});

describe('decide: acting on oneself', () => {
  for (const role of ALL_ROLES) {
    for (const action of ALL_ACCESS_ACTIONS) {
      it(`refuses ${role} performing ${action} on itself`, () => {
        const self: PolicySubject = { id: ACTOR_ID, role };
        const decision = decide(self, { action, role: Role.USER }, self);

        expect(decision.allowed).toBe(false);

        // A staff actor is refused by the self rule itself, before any other
        // rule; a USER/ATHLETE is already refused for having no such action.
        if (role === Role.ADMIN || role === Role.OWNER) {
          expect(decision).toEqual({ allowed: false, reason: 'self_action' });
        }
      });
    }
  }
});

describe('decide: deny is the default', () => {
  it('refuses an unknown actor role', () => {
    const decision = decide(
      { id: ACTOR_ID, role: 'SUPERUSER' as Role },
      request(AccessAction.USER_BLOCK),
      targetOf(Role.USER),
    );

    expect(decision).toEqual({ allowed: false, reason: 'unknown_actor_role' });
  });

  it('refuses an unknown target role', () => {
    const decision = decide(actorOf(Role.OWNER), request(AccessAction.USER_BLOCK), {
      id: TARGET_ID,
      role: 'SUPERUSER' as Role,
    });

    expect(decision).toEqual({ allowed: false, reason: 'unknown_target_role' });
  });

  it('refuses an action outside the closed set', () => {
    expect(decide(actorOf(Role.OWNER), { action: 'user.explode' }, targetOf(Role.USER))).toEqual({
      allowed: false,
      reason: 'unknown_action',
    });
    expect(decide(actorOf(Role.OWNER), { action: 'USER_BLOCK' }, targetOf(Role.USER))).toEqual({
      allowed: false,
      reason: 'unknown_action',
    });
  });

  it('refuses a role change without a usable requested role', () => {
    expect(
      decide(actorOf(Role.OWNER), { action: AccessAction.USER_CHANGE_ROLE }, targetOf(Role.USER)),
    ).toEqual({ allowed: false, reason: 'unknown_requested_role' });
    expect(
      decide(
        actorOf(Role.OWNER),
        { action: AccessAction.USER_CHANGE_ROLE, role: 'SUPERUSER' },
        targetOf(Role.USER),
      ),
    ).toEqual({ allowed: false, reason: 'unknown_requested_role' });
  });

  it('names the rule for representative refusals', () => {
    const cases: readonly [AccessAction, Role, Role, string][] = [
      [AccessAction.USER_BLOCK, Role.ADMIN, Role.OWNER, 'target_is_owner'],
      [AccessAction.USER_BLOCK, Role.ADMIN, Role.ADMIN, 'admin_target_not_permitted'],
      [AccessAction.USER_DELETE, Role.ADMIN, Role.USER, 'admin_delete_forbidden'],
      [AccessAction.ADMIN_GRANT, Role.ADMIN, Role.USER, 'admin_management_requires_owner'],
      [AccessAction.USER_CHANGE_ROLE, Role.ADMIN, Role.USER, 'admin_management_requires_owner'],
      [AccessAction.OWNER_GRANT, Role.OWNER, Role.USER, 'owner_grant_forbidden'],
      [AccessAction.ADMIN_GRANT, Role.OWNER, Role.ADMIN, 'target_already_admin'],
      [AccessAction.ADMIN_REVOKE, Role.OWNER, Role.USER, 'target_not_admin'],
    ];

    for (const [action, actorRole, targetRole, reason] of cases) {
      const decision = decide(
        actorOf(actorRole),
        { action, role: Role.USER },
        targetOf(targetRole),
      );

      expect(decision).toEqual({ allowed: false, reason });
    }
  });
});
