import { randomUUID } from 'node:crypto';
import { Role } from '../src/auth/roles';
import { createAdminHarness, type AdminHarness } from './helpers/admin-harness';

/**
 * Demotion over HTTP, with no database and no Redis.
 *
 * What must hold: only the owner may demote, the demoted account loses every
 * token it held as staff, it is an ordinary account again on the next request,
 * and every refusal keeps the bytes the other admin routes return.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;

/** Bodies carry a per-request id; two refusals are compared without it. */
const withoutRequestId = (body: unknown): unknown => ({
  ...(body as Record<string, unknown>),
  requestId: '-',
});

describe('Admin revoke (e2e)', () => {
  let admin: AdminHarness;

  const adminPath = (userId: string) => `/admin/users/${userId}/admin`;

  beforeAll(async () => {
    admin = await createAdminHarness('revoke_user');
  });

  afterAll(async () => {
    await admin.close();
  });

  it('demotes an admin when the owner stepped up', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const target = await admin.signUp(Role.USER);

    expect((await admin.post(adminPath(target.userId), owner.token)).status).toBe(204);

    // A session created while the account was staff: this is the one to cut.
    const staffToken = await admin.signIn(target);

    expect((await admin.get('/test/protected', staffToken)).status).toBe(403);
    expect((await admin.del(adminPath(target.userId), owner.token)).status).toBe(204);

    expect(admin.sessions.users.get(target.userId)?.role).toBe(Role.USER);
    expect(admin.rows('admin.admin.revoke', target.userId).map((row) => row.metadata)).toEqual([
      { from: Role.ADMIN, to: Role.USER },
    ]);
    // The old token is gone, not merely downgraded.
    expect((await admin.get('/test/protected', staffToken)).status).toBe(401);
  });

  it('leaves a demoted account as an ordinary user', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const target = await admin.signUp(Role.USER);
    const other = await admin.signUp(Role.USER);

    expect((await admin.post(adminPath(target.userId), owner.token)).status).toBe(204);
    expect((await admin.del(adminPath(target.userId), owner.token)).status).toBe(204);

    const token = await admin.signIn(target);

    // No staff gate any more, and no admin route either.
    expect((await admin.get('/test/protected', token)).status).toBe(200);
    expect((await admin.del(adminPath(other.userId), token)).status).toBe(403);
    expect(admin.rows('admin.admin.revoke', target.userId)).toHaveLength(1);
  });

  it('refuses an admin actor on a peer and on itself', async () => {
    const actor = await admin.signUp(Role.ADMIN, true);
    const peer = await admin.signUp(Role.ADMIN);

    const onPeer = await admin.del(adminPath(peer.userId), actor.token);
    const onSelf = await admin.del(adminPath(actor.userId), actor.token);

    expect(onPeer.status).toBe(403);
    expect(onPeer.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    expect(withoutRequestId(onSelf.body)).toEqual(withoutRequestId(onPeer.body));
    expect(admin.sessions.users.get(peer.userId)?.role).toBe(Role.ADMIN);
    expect(admin.sessions.users.get(actor.userId)?.role).toBe(Role.ADMIN);
    expect(admin.rows('admin.admin.revoke', peer.userId)).toHaveLength(0);
    expect(admin.rows('admin.admin.revoke', actor.userId)).toHaveLength(0);
  });

  it('answers a user, the owner and an unknown id alike', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const otherOwner = await admin.signUp(Role.OWNER);
    const member = await admin.signUp(Role.USER);

    const bodies: unknown[] = [];

    for (const id of [otherOwner.userId, member.userId, randomUUID(), 'not-a-uuid']) {
      const refused = await admin.del(adminPath(id), owner.token);

      expect(refused.status).toBe(403);
      bodies.push(withoutRequestId(refused.body));
    }

    expect(bodies[0]).toEqual({ ...FORBIDDEN, requestId: '-' });
    expect(new Set(bodies.map((body) => JSON.stringify(body))).size).toBe(1);
    expect(admin.sessions.users.get(member.userId)?.role).toBe(Role.USER);
    expect(admin.sessions.users.get(otherOwner.userId)?.role).toBe(Role.OWNER);
    expect(admin.rows('admin.admin.revoke', member.userId)).toHaveLength(0);
    expect(admin.rows('admin.admin.revoke', otherOwner.userId)).toHaveLength(0);
  });

  it('needs the second factor before the policy is asked', async () => {
    const owner = await admin.signUp(Role.OWNER);
    const target = await admin.signUp(Role.ADMIN);

    const refused = await admin.del(adminPath(target.userId), owner.token);

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({
      statusCode: 403,
      message: 'Forbidden',
      code: 'second_factor_required',
      requestId: expect.any(String),
    });
    expect(admin.sessions.users.get(target.userId)?.role).toBe(Role.ADMIN);
    expect(admin.rows('admin.admin.revoke', target.userId)).toHaveLength(0);
  });

  it('demotes once when two revokes arrive together', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const target = await admin.signUp(Role.ADMIN);

    const attempts = await Promise.all([
      admin.del(adminPath(target.userId), owner.token),
      admin.del(adminPath(target.userId), owner.token),
    ]);
    const statuses = attempts.map((attempt) => attempt.status).sort();

    // The one that acted gets 204; the other either finished the same demotion
    // or found a non-admin target and got the generic refusal.
    expect(statuses[0]).toBe(204);
    expect(statuses.filter((status) => status === 204 || status === 403)).toHaveLength(2);
    expect(admin.sessions.users.get(target.userId)?.role).toBe(Role.USER);
    expect(admin.rows('admin.admin.revoke', target.userId)).toHaveLength(1);
  });
});
