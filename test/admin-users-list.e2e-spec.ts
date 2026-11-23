import { createHash } from 'node:crypto';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { Role } from '../src/auth/roles';
import { STEPUP_WINDOW_MS } from '../src/auth/totp/step-up.guard';
import { createAdminHarness, type AdminAccount, type AdminHarness } from './helpers/admin-harness';

/**
 * `GET /admin/users` over HTTP, with no database and no Redis.
 *
 * What must hold: the route sits behind the same gates as the mutations, the
 * page carries the allowlist and nothing else, the three filters read the
 * stored columns, a page outside the contract is a 400, and every served page
 * leaves exactly one trail row - with the address filter hashed, not written.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;
const SECOND_FACTOR_REQUIRED = { ...FORBIDDEN, code: 'second_factor_required' } as const;
const STEP_UP_REQUIRED = { ...FORBIDDEN, code: 'step_up_required' } as const;
const ACTION = 'admin.users.list';

/** Every seeded row sits in January 2026, so the sign-up order cannot matter. */
const T0 = Date.UTC(2026, 0, 1);
const at = (minute: number): Date => new Date(T0 + minute * 60_000);

interface ListBody {
  readonly users: {
    readonly id: string;
    readonly username: string;
    readonly email: string | null;
    readonly role: string;
    readonly status: string;
    readonly createdAt: string;
  }[];
  readonly page: number;
  readonly pageSize: number;
  readonly total: number;
}

const usernames = (body: unknown): string[] =>
  (body as ListBody).users.map((user) => user.username);

describe('Admin user list (e2e)', () => {
  let admin: AdminHarness;
  let app: NestExpressApplication;
  let owner: AdminAccount;
  let staff: AdminAccount;
  let stalled: AdminAccount;
  let unstamped: AdminAccount;
  let member: AdminAccount;
  let athlete: AdminAccount;

  beforeAll(async () => {
    admin = await createAdminHarness('list_user');
    app = admin.app;
    owner = await admin.signUp(Role.OWNER, true);
    staff = await admin.signUp(Role.ADMIN, true);
    stalled = await admin.signUp(Role.ADMIN, true);
    unstamped = await admin.signUp(Role.ADMIN);
    member = await admin.signUp(Role.USER);
    athlete = await admin.signUp(Role.ATHLETE);

    // A step-up that happened before the window: staff, but not fresh enough.
    const session = admin.sessions.sessions.get(stalled.sessionId);

    if (session === undefined) throw new Error('the step-up session was not stored');

    session.stepupAt = new Date(Date.now() - STEPUP_WINDOW_MS - 60_000);

    admin.sessions.seedUser({
      phone: null,
      username: 'list_early',
      email: 'early@example.com',
      role: Role.USER,
      createdAt: at(0),
    });
    admin.sessions.seedUser({
      phone: null,
      username: 'list_late',
      email: 'late@example.com',
      status: 'BLOCKED',
      createdAt: at(1),
    });
  });

  afterAll(async () => {
    await admin.close();
  });

  it('refuses an anonymous caller without writing a row', async () => {
    const before = admin.rows(ACTION).length;
    const response = await request(app.getHttpServer()).get('/admin/users');

    expect(response.status).toBe(401);
    expect(admin.rows(ACTION)).toHaveLength(before);
  });

  it('refuses a non-staff caller with the shared bytes', async () => {
    for (const account of [member, athlete]) {
      const response = await admin.get('/admin/users', account.token);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    }

    expect(admin.rows(ACTION)).toHaveLength(0);
  });

  it('demands a second factor and a fresh step-up from staff', async () => {
    const withoutFactor = await admin.get('/admin/users', unstamped.token);

    expect(withoutFactor.status).toBe(403);
    expect(withoutFactor.body).toEqual({
      ...SECOND_FACTOR_REQUIRED,
      requestId: expect.any(String),
    });

    const stale = await admin.get('/admin/users', stalled.token);

    expect(stale.status).toBe(403);
    expect(stale.body).toEqual({ ...STEP_UP_REQUIRED, requestId: expect.any(String) });
    expect(admin.rows(ACTION)).toHaveLength(0);
  });

  it('serves one page of the allowlist, oldest first', async () => {
    const response = await admin.get('/admin/users?page=1&pageSize=2', owner.token);

    expect(response.status).toBe(200);

    const body = response.body as ListBody;

    expect(body.page).toBe(1);
    expect(body.pageSize).toBe(2);
    expect(body.total).toBeGreaterThanOrEqual(2);
    expect(usernames(body)).toEqual(['list_early', 'list_late']);
    expect(Object.keys(body.users[0] ?? {}).sort()).toEqual([
      'createdAt',
      'email',
      'id',
      'role',
      'status',
      'username',
    ]);
    // No hash, no phone and no second-factor state ever reaches the page.
    expect(JSON.stringify(body)).not.toContain('passwordHash');
    expect(JSON.stringify(body)).not.toContain('phone');
    expect(JSON.stringify(body)).not.toContain('identityVerifier');
  });

  it('cuts the next page without repeating or skipping a row', async () => {
    const first = await admin.get('/admin/users?page=1&pageSize=2', owner.token);
    const second = await admin.get('/admin/users?page=2&pageSize=2', owner.token);
    const both = [...usernames(first.body), ...usernames(second.body)];

    expect(second.status).toBe(200);
    expect(new Set(both).size).toBe(both.length);
    expect(usernames(second.body)).toHaveLength(2);
  });

  it('rejects a page or a filter outside the contract', async () => {
    const before = admin.rows(ACTION).length;

    for (const query of [
      'page=0',
      'page=abc',
      'pageSize=0',
      'pageSize=101',
      'role=SUPERUSER',
      'blocked=yes',
      'email=not-an-address',
      // The whitelist pipe is on: a key the DTO does not name is a 400.
      'unknown=1',
    ]) {
      const response = await admin.get(`/admin/users?${query}`, owner.token);

      expect(response.status).toBe(400);
    }

    expect(admin.rows(ACTION)).toHaveLength(before);
  });

  it('filters on the stored role, status and address', async () => {
    const admins = await admin.get('/admin/users?role=ADMIN&pageSize=100', owner.token);

    expect(admins.status).toBe(200);
    expect((admins.body as ListBody).users.length).toBeGreaterThanOrEqual(3);
    expect((admins.body as ListBody).users.every((user) => user.role === Role.ADMIN)).toBe(true);

    const blocked = await admin.get('/admin/users?blocked=true&pageSize=100', owner.token);
    expect(usernames(blocked.body)).toEqual(['list_late']);

    const active = await admin.get('/admin/users?blocked=false&pageSize=100', owner.token);
    expect(usernames(active.body)).not.toContain('list_late');

    // The address is normalised on the way in, so the uppercase spelling hits.
    const byAddress = await admin.get('/admin/users?email=EARLY@Example.COM', owner.token);
    expect(usernames(byAddress.body)).toEqual(['list_early']);
  });

  it('records one trail row per listing, with the address filter hashed', async () => {
    const before = admin.rows(ACTION).length;
    const response = await admin.get('/admin/users?email=early@example.com', owner.token);

    expect(response.status).toBe(200);

    const rows = admin.rows(ACTION);

    expect(rows).toHaveLength(before + 1);

    const row = rows[rows.length - 1];

    expect(row?.actorId).toBe(owner.userId);
    expect(row?.metadata).toMatchObject({
      addressFilterSha256: createHash('sha256').update('early@example.com').digest('hex'),
      results: 1,
      total: 1,
    });
    expect(JSON.stringify(row?.metadata)).not.toContain('early@example.com');
  });
});
