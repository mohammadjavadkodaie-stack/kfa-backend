import { createHash } from 'node:crypto';
import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import { InMemorySessionRepository } from '../auth/in-memory-session.repository';
import type { PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { InMemoryTotpRepository } from '../auth/totp/in-memory-totp.repository';
import { AdminUsersQueryDto, toAdminUsersFilter } from './admin-users.dto';
import { ADMIN_AUDIT_ACTIONS, AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier } from './owner-notifier';

/**
 * `GET /admin/users` at the service boundary: the allowlist, the page maths,
 * the three filters and the trail row. The e2e suite proves the gates and the
 * query string; this one proves that nothing else can reach the page.
 */

const OWNER: PolicySubject = { id: '11111111-1111-4111-8111-111111111111', role: Role.OWNER };
const ADMIN: PolicySubject = { id: '22222222-2222-4222-8222-222222222222', role: Role.ADMIN };
const MEMBER: PolicySubject = { id: '33333333-3333-4333-8333-333333333333', role: Role.USER };
const ATHLETE: PolicySubject = { id: '44444444-4444-4444-8444-444444444444', role: Role.ATHLETE };
const REQUEST_ID = 'req-list';

/** Every seeded row sits in January 2026, so the seed order decides the list. */
const T0 = Date.UTC(2026, 0, 1);
const at = (minute: number): Date => new Date(T0 + minute * 60_000);
const ALL = { page: 1, pageSize: 20 };

interface WarnCall {
  readonly payload: unknown;
  readonly message: unknown;
}

class RecordingLogger {
  readonly warns: WarnCall[] = [];

  info(): void {}

  warn(payload: unknown, message?: unknown): void {
    this.warns.push({ payload, message });
  }
}

/** An audit trail that cannot be written: the listing must not be served. */
class FailingAudit extends FakeAudit {
  override async record(entry: AuditRecord): Promise<void> {
    await super.record(entry);

    throw new Error('audit chain is unavailable');
  }
}

function createHarness(audit: FakeAudit = new FakeAudit()) {
  const sessions = new InMemorySessionRepository();
  const logger = new RecordingLogger();
  const policy = new AccessPolicyService(
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );
  const service = new AdminUsersService(
    sessions,
    new InMemoryTotpRepository(),
    policy,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    new LogOwnerNotifier(logger as unknown as PinoLogger),
  );

  return { service, sessions, audit, logger };
}

describe('AdminUsersService.list', () => {
  it('returns the allowlist for one page, oldest first', async () => {
    const { service, sessions } = createHarness();
    const owner = sessions.seedUser({
      phone: '+14155550100',
      username: 'ivan',
      email: 'ivan@example.com',
      role: Role.OWNER,
      createdAt: at(0),
    });
    const member = sessions.seedUser({ phone: null, username: 'petra', createdAt: at(1) });

    await expect(service.list(OWNER, ALL, REQUEST_ID)).resolves.toEqual({
      users: [
        {
          id: owner.id,
          username: 'ivan',
          email: 'ivan@example.com',
          role: Role.OWNER,
          status: 'ACTIVE',
          createdAt: at(0).toISOString(),
        },
        {
          id: member.id,
          username: 'petra',
          email: null,
          role: Role.USER,
          status: 'ACTIVE',
          createdAt: at(1).toISOString(),
        },
      ],
      page: 1,
      pageSize: 20,
      total: 2,
    });
  });

  it('cuts a page out of the whole set and reports the unfiltered total', async () => {
    const { service, sessions } = createHarness();
    const ids = Array.from(
      { length: 25 },
      (_unused, index) =>
        sessions.seedUser({
          phone: null,
          username: `user${String(index).padStart(2, '0')}`,
          createdAt: at(index),
        }).id,
    );

    const page = await service.list(ADMIN, { page: 3, pageSize: 10 }, REQUEST_ID);

    expect(page.page).toBe(3);
    expect(page.total).toBe(25);
    expect(page.users.map((user) => user.id)).toEqual(ids.slice(20));
  });

  it('honours the role, blocked and address filters', async () => {
    const { service, sessions } = createHarness();
    sessions.seedUser({
      phone: null,
      username: 'active_admin',
      role: Role.ADMIN,
      createdAt: at(0),
    });
    sessions.seedUser({
      phone: null,
      username: 'blocked_member',
      status: 'BLOCKED',
      createdAt: at(1),
    });
    sessions.seedUser({
      phone: null,
      username: 'addressed',
      email: 'addressed@example.com',
      createdAt: at(2),
    });

    const admins = await service.list(ADMIN, { ...ALL, role: Role.ADMIN }, REQUEST_ID);
    expect(admins.users.map((user) => user.username)).toEqual(['active_admin']);

    const blocked = await service.list(ADMIN, { ...ALL, blocked: true }, REQUEST_ID);
    expect(blocked.users.map((user) => user.username)).toEqual(['blocked_member']);
    expect(blocked.total).toBe(1);

    const active = await service.list(ADMIN, { ...ALL, blocked: false }, REQUEST_ID);
    expect(active.users.map((user) => user.username)).toEqual(['active_admin', 'addressed']);

    const byAddress = await service.list(
      ADMIN,
      { ...ALL, email: 'addressed@example.com' },
      REQUEST_ID,
    );
    expect(byAddress.users.map((user) => user.username)).toEqual(['addressed']);
  });

  it('records one trail row per listing, with the address filter hashed', async () => {
    const audit = new FakeAudit();
    const { service, sessions } = createHarness(audit);
    sessions.seedUser({ phone: null, username: 'addressed', email: 'addressed@example.com' });

    await service.list(
      ADMIN,
      { page: 1, pageSize: 5, role: Role.USER, blocked: false, email: 'addressed@example.com' },
      REQUEST_ID,
    );

    expect(audit.records).toHaveLength(1);
    expect(audit.records[0]).toMatchObject({
      action: ADMIN_AUDIT_ACTIONS.USERS_LIST,
      actorId: ADMIN.id,
      metadata: {
        page: 1,
        pageSize: 5,
        role: Role.USER,
        blocked: false,
        addressFilterSha256: createHash('sha256').update('addressed@example.com').digest('hex'),
        results: 1,
        total: 1,
      },
    });
    expect(JSON.stringify(audit.records[0])).not.toContain('addressed@example.com');
  });

  it('refuses a caller who is not staff without writing a row', async () => {
    const { service, audit } = createHarness();

    for (const actor of [MEMBER, ATHLETE]) {
      await expect(service.list(actor, ALL, REQUEST_ID)).rejects.toThrow(ForbiddenException);
    }

    expect(audit.records).toHaveLength(0);
  });

  it('refuses to serve a listing it could not record', async () => {
    const { service, logger } = createHarness(new FailingAudit());

    await expect(service.list(ADMIN, ALL, REQUEST_ID)).rejects.toThrow(ServiceUnavailableException);
    expect(logger.warns).toHaveLength(1);
  });
});

describe('toAdminUsersFilter', () => {
  it('applies the documented defaults', () => {
    expect(toAdminUsersFilter(new AdminUsersQueryDto())).toEqual({ page: 1, pageSize: 20 });
  });

  it('turns the blocked spelling into a boolean and keeps the page', () => {
    const query = new AdminUsersQueryDto();
    query.role = Role.ADMIN;
    query.blocked = 'true';
    query.page = 2;
    query.pageSize = 50;

    expect(toAdminUsersFilter(query)).toEqual({
      page: 2,
      pageSize: 50,
      role: Role.ADMIN,
      blocked: true,
    });
  });
});
