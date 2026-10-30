import { Role } from '../src/auth/roles';
import { base32Decode, totpAt } from '../src/auth/totp';
import { createAdminHarness, type AdminAccount, type AdminHarness } from './helpers/admin-harness';

/**
 * The owner-initiated second-factor reset over HTTP, with no database and no
 * Redis.
 *
 * What must hold: only the owner may clear a factor, the account loses the
 * credential and every token it held, and on the next sign-in the staff gate
 * keeps it on the second-factor routes until it enrolls again.
 */

const SECOND_FACTOR_REQUIRED = {
  statusCode: 403,
  message: 'Forbidden',
  code: 'second_factor_required',
} as const;

describe('Admin TOTP reset (e2e)', () => {
  let admin: AdminHarness;

  const resetPath = (userId: string) => `/admin/users/${userId}/totp/reset`;

  /** Enrolment plus confirmation over the real endpoints; the session ends proven. */
  async function enroll(account: AdminAccount): Promise<void> {
    const started = await admin.post('/auth/totp/enroll', account.token);

    expect(started.status).toBe(200);

    const secret = base32Decode((started.body as { secretBase32: string }).secretBase32);
    const confirmed = await admin.post('/auth/totp/confirm', account.token, {
      code: totpAt(secret, Date.now()),
    });

    expect(confirmed.status).toBe(200);
  }

  beforeAll(async () => {
    admin = await createAdminHarness('reset_user');
  });

  afterAll(async () => {
    await admin.close();
  });

  it('clears the factor and cuts every token of the target', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const target = await admin.signUp(Role.ADMIN, true);

    await enroll(target);

    expect((await admin.get('/auth/totp/status', target.token)).body).toEqual({
      confirmed: true,
      recoveryCodesLeft: 10,
    });
    expect((await admin.post(resetPath(target.userId), owner.token)).status).toBe(204);

    // The old token is dead, so the status route cannot be asked with it.
    expect((await admin.get('/auth/totp/status', target.token)).status).toBe(401);
    expect(admin.sessions.users.get(target.userId)?.role).toBe(Role.ADMIN);
    expect(admin.rows('admin.totp.reset', target.userId)).toHaveLength(1);
  });

  it('keeps the target on the second-factor routes until it enrolls again', async () => {
    const owner = await admin.signUp(Role.OWNER, true);
    const target = await admin.signUp(Role.ADMIN, true);

    await enroll(target);
    expect((await admin.post(resetPath(target.userId), owner.token)).status).toBe(204);

    const token = await admin.signIn(target);
    const closed = await admin.get('/test/protected', token);

    expect(closed.status).toBe(403);
    expect(closed.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });

    const empty = await admin.get('/auth/totp/status', token);

    expect(empty.status).toBe(200);
    expect(empty.body).toEqual({ confirmed: false, recoveryCodesLeft: 0 });

    // Enrolment starts from scratch: the old secret and codes are gone.
    const started = await admin.post('/auth/totp/enroll', token);

    expect(started.status).toBe(200);

    const secret = base32Decode((started.body as { secretBase32: string }).secretBase32);
    const confirmed = await admin.post('/auth/totp/confirm', token, {
      code: totpAt(secret, Date.now()),
    });

    expect(confirmed.status).toBe(200);
    expect((await admin.get('/test/protected', token)).status).toBe(200);
    expect(admin.rows('admin.totp.reset', target.userId)).toHaveLength(1);
  });

  it('needs a fresh second factor before the policy is asked', async () => {
    const owner = await admin.signUp(Role.OWNER);
    const target = await admin.signUp(Role.ADMIN, true);

    await enroll(target);

    const refused = await admin.post(resetPath(target.userId), owner.token);

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ ...SECOND_FACTOR_REQUIRED, requestId: expect.any(String) });
    expect(admin.rows('admin.totp.reset', target.userId)).toHaveLength(0);
    // The refused call left the factor untouched.
    expect((await admin.get('/auth/totp/status', target.token)).body).toEqual({
      confirmed: true,
      recoveryCodesLeft: 10,
    });
  });
});
