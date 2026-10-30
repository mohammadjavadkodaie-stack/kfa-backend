import { METHOD_METADATA } from '@nestjs/common/constants';
import { AdminUsersController } from '../src/admin/admin-users.controller';
import { ROLES_KEY } from '../src/auth/decorators/roles.decorator';
import { Role } from '../src/auth/roles';
import { STEPUP_WINDOW_MS, STEP_UP_REQUIRED_KEY } from '../src/auth/totp/step-up.guard';
import { createAdminHarness, type AdminAccount, type AdminHarness } from './helpers/admin-harness';

/**
 * The five admin routes as one surface, checked once over the whole set: every
 * refusal looks the same from outside, both gates refuse in their own words,
 * every handler carries the markers, and a doubled request records one row.
 *
 * Earlier suites prove each route on its own; this one exists so a sixth route
 * cannot arrive with weaker refusal bytes or without a step-up.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;
const SECOND_FACTOR_REQUIRED = { ...FORBIDDEN, code: 'second_factor_required' } as const;
const STEP_UP_REQUIRED = { ...FORBIDDEN, code: 'step_up_required' } as const;

/** The surface, by verb and suffix: `grant` and `revoke` share a path. */
const ROUTES = [
  { path: 'block', method: 'POST' },
  { path: 'unblock', method: 'POST' },
  { path: 'admin', method: 'POST' },
  { path: 'admin', method: 'DELETE' },
  { path: 'totp/reset', method: 'POST' },
] as const;

/** The handlers that answer `ROUTES`, in the order above. */
const HANDLERS = ['block', 'unblock', 'grantAdmin', 'revokeAdmin', 'resetTotp'] as const;

/** Bodies carry a per-request id; two refusals are compared without it. */
const withoutRequestId = (body: unknown): Record<string, unknown> => ({
  ...(body as Record<string, unknown>),
  requestId: '-',
});

describe('Admin surface (e2e)', () => {
  let admin: AdminHarness;
  let owner: AdminAccount;
  let staff: AdminAccount;
  let peer: AdminAccount;
  let member: AdminAccount;
  let athlete: AdminAccount;

  const send = (route: (typeof ROUTES)[number], id: string, token?: string) => {
    const path = `/admin/users/${id}/${route.path}`;

    return route.method === 'DELETE' ? admin.del(path, token) : admin.post(path, token);
  };

  beforeAll(async () => {
    admin = await createAdminHarness('surface_user');
    owner = await admin.signUp(Role.OWNER);
    staff = await admin.signUp(Role.ADMIN, true);
    peer = await admin.signUp(Role.ADMIN);
    member = await admin.signUp(Role.USER);
    athlete = await admin.signUp(Role.ATHLETE);
  });

  afterAll(async () => {
    await admin.close();
  });

  it('refuses every actor and target with the same bytes', async () => {
    const bodies: Record<string, unknown>[] = [];

    for (const route of ROUTES) {
      const attempts = [
        // The owner row is never a target, whoever asks.
        await send(route, owner.userId, staff.token),
        // An admin cannot act on itself or on a peer.
        await send(route, staff.userId, staff.token),
        await send(route, peer.userId, staff.token),
        // A route marker, not the policy, answers a non-staff caller.
        await send(route, member.userId, member.token),
        await send(route, member.userId, athlete.token),
      ];

      for (const attempt of attempts) {
        expect(attempt.status).toBe(403);
        bodies.push(withoutRequestId(attempt.body));
      }
    }

    expect(bodies[0]).toEqual({ ...FORBIDDEN, requestId: '-' });
    expect(new Set(bodies.map((body) => JSON.stringify(body))).size).toBe(1);

    // Nothing about the actor, the target, the role or the second factor.
    const text = JSON.stringify(bodies[0]);

    expect(text).not.toMatch(/ADMIN|OWNER|role|totp|verifier|count/i);

    for (const account of [owner, staff, peer, member, athlete]) {
      expect(text).not.toContain(account.userId);
    }

    expect(admin.sessions.users.get(peer.userId)?.role).toBe(Role.ADMIN);
    expect(admin.sessions.users.get(member.userId)?.role).toBe(Role.USER);
    expect(admin.rows('admin.admin.grant')).toHaveLength(0);
    expect(admin.rows('admin.admin.revoke')).toHaveLength(0);
    expect(admin.rows('admin.totp.reset')).toHaveLength(0);
  });

  it('closes every route without a second factor, then without a fresh one', async () => {
    const unproven = await admin.signUp(Role.OWNER);
    const proven = await admin.signUp(Role.OWNER, true);
    const session = admin.sessions.sessions.get(proven.sessionId);

    if (session === undefined) throw new Error('the owner session is missing');

    // Older than the window the guard accepts, and not a second in the future.
    session.stepupAt = new Date(Date.now() - STEPUP_WINDOW_MS - 1_000);

    for (const route of ROUTES) {
      const closed = await send(route, member.userId, unproven.token);
      const stale = await send(route, member.userId, proven.token);

      expect(closed.status).toBe(403);
      expect(closed.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
      expect(stale.status).toBe(403);
      expect(stale.body).toEqual({ ...STEP_UP_REQUIRED, requestId: expect.any(String) });
    }

    expect(admin.rows('admin.user.block', member.userId)).toHaveLength(0);
    expect(admin.rows('admin.admin.grant')).toHaveLength(0);
    expect(admin.rows('admin.totp.reset')).toHaveLength(0);
  });

  it('marks every route of the controller with staff roles and a step-up', () => {
    const prototype = AdminUsersController.prototype as unknown as Record<string, unknown>;
    const handlers = Object.getOwnPropertyNames(prototype).filter((name) => {
      const handler = prototype[name];

      return (
        typeof handler === 'function' && Reflect.getMetadata(METHOD_METADATA, handler) !== undefined
      );
    });

    // A route added to the controller without a row here fails this comparison.
    expect(handlers.sort()).toEqual([...HANDLERS].sort());

    for (const name of handlers) {
      const handler = prototype[name] as object;

      expect(Reflect.getMetadata(ROLES_KEY, handler)).toEqual([Role.ADMIN, Role.OWNER]);
      expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handler)).toBe(true);
    }
  });

  it('records one row for each doubled request', async () => {
    const promoter = await admin.signUp(Role.OWNER, true);
    const blocked = await admin.signUp(Role.USER);
    const promoted = await admin.signUp(Role.USER);

    const blocks = await Promise.all([
      admin.post(`/admin/users/${blocked.userId}/block`, staff.token),
      admin.post(`/admin/users/${blocked.userId}/block`, staff.token),
    ]);
    const grants = await Promise.all([
      admin.post(`/admin/users/${promoted.userId}/admin`, promoter.token),
      admin.post(`/admin/users/${promoted.userId}/admin`, promoter.token),
    ]);

    expect(blocks.map((call) => call.status)).toEqual([204, 204]);
    expect(grants.map((call) => call.status)).toEqual([204, 204]);
    expect(admin.rows('admin.user.block', blocked.userId)).toHaveLength(1);
    expect(admin.rows('admin.admin.grant', promoted.userId)).toHaveLength(1);
  });
});
