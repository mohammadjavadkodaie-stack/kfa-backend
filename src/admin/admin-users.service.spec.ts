import { ServiceUnavailableException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import { InMemorySessionRepository } from '../auth/in-memory-session.repository';
import { AccessAction, type PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { ADMIN_AUDIT_ACTIONS, AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier } from './owner-notifier';

const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const ADMIN_ID = '22222222-2222-4222-8222-222222222222';
const PEER_ADMIN_ID = '33333333-3333-4333-8333-333333333333';
const USER_ID = '44444444-4444-4444-8444-444444444444';
const UNKNOWN_ID = '55555555-5555-4555-8555-555555555555';
/** Never passed to the service; proves nothing contact-like is recorded. */
const PHONE = '+14155550123';
const USERNAME = 'ivan';
const REQUEST_ID = 'req-admin';

const OWNER: PolicySubject = { id: OWNER_ID, role: Role.OWNER };
const ADMIN: PolicySubject = { id: ADMIN_ID, role: Role.ADMIN };
const MEMBER: PolicySubject = { id: USER_ID, role: Role.USER };

interface LogCall {
  readonly payload: Record<string, unknown>;
  readonly message: unknown;
}

class RecordingLogger {
  readonly infos: LogCall[] = [];
  readonly warns: LogCall[] = [];

  info(payload: Record<string, unknown>, message?: unknown): void {
    this.infos.push({ payload, message });
  }

  warn(payload: Record<string, unknown>, message?: unknown): void {
    this.warns.push({ payload, message });
  }
}

/** An audit trail that cannot be written: the action must fail with it. */
class FailingAudit extends FakeAudit {
  override async record(entry: AuditRecord): Promise<void> {
    await super.record(entry);

    throw new Error('audit chain is unavailable');
  }
}

/** Proves the helper reuses the repository method instead of reimplementing it. */
class RecordingSessions extends InMemorySessionRepository {
  readonly revokedAll: { userId: string; reason: string }[] = [];

  override async revokeAllUserSessions(userId: string, reason: string): Promise<void> {
    this.revokedAll.push({ userId, reason });
  }
}

class FailingSessions extends InMemorySessionRepository {
  override async revokeAllUserSessions(): Promise<void> {
    throw new Error('sessions are unavailable');
  }
}

class CountingSessions extends InMemorySessionRepository {
  lookups = 0;

  override async findUserById(userId: string) {
    this.lookups += 1;

    return super.findUserById(userId);
  }
}

function createHarness(
  audit: FakeAudit = new FakeAudit(),
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
) {
  const policy = new AccessPolicyService(
    audit as unknown as AuditService,
    new RecordingLogger() as unknown as PinoLogger,
  );
  const logger = new RecordingLogger();
  const service = new AdminUsersService(
    sessions,
    policy,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, sessions, audit, logger };
}

describe('in-memory CAS', () => {
  it('changes the status once', async () => {
    const sessions = new InMemorySessionRepository();
    const { id } = sessions.seedUser({ phone: PHONE, username: USERNAME });

    await expect(sessions.setStatusIf(id, 'ACTIVE', 'BLOCKED')).resolves.toBe(true);
    await expect(sessions.setStatusIf(id, 'ACTIVE', 'BLOCKED')).resolves.toBe(false);
    await expect(sessions.findUserById(id)).resolves.toMatchObject({ status: 'BLOCKED' });
  });

  it('changes the role once', async () => {
    const sessions = new InMemorySessionRepository();
    const { id } = sessions.seedUser({ phone: PHONE, username: USERNAME });

    await expect(sessions.setRoleIf(id, Role.USER, Role.ADMIN)).resolves.toBe(true);
    await expect(sessions.setRoleIf(id, Role.USER, Role.ADMIN)).resolves.toBe(false);
    await expect(sessions.findUserById(id)).resolves.toMatchObject({ role: Role.ADMIN });
  });

  it('refuses a stale expectation', async () => {
    const sessions = new InMemorySessionRepository();
    const { id } = sessions.seedUser({ phone: PHONE, username: USERNAME });

    await expect(sessions.setStatusIf(id, 'BLOCKED', 'ACTIVE')).resolves.toBe(false);
    await expect(sessions.setRoleIf(id, Role.ADMIN, Role.USER)).resolves.toBe(false);
    await expect(sessions.findUserById(id)).resolves.toMatchObject({
      role: Role.USER,
      status: 'ACTIVE',
    });
  });
});

describe('loadTarget', () => {
  it('answers a malformed id exactly like an unknown one', async () => {
    const { service } = createHarness();

    const malformed = await service.loadTarget('not-a-uuid');
    const unknown = await service.loadTarget(UNKNOWN_ID);

    expect(malformed).toBe(unknown);
    expect(malformed).toEqual({ found: false });
  });

  it('never asks storage about a malformed id', async () => {
    const sessions = new CountingSessions();
    const { service } = createHarness(new FakeAudit(), sessions);

    await service.loadTarget('not-a-uuid');

    expect(sessions.lookups).toBe(0);
  });

  it('returns the stored role and status', async () => {
    const { service, sessions } = createHarness();
    const { id } = sessions.seedUser({
      phone: PHONE,
      username: USERNAME,
      role: Role.ADMIN,
      status: 'BLOCKED',
    });

    await expect(service.loadTarget(id)).resolves.toEqual({
      found: true,
      target: { id, role: Role.ADMIN, status: 'BLOCKED' },
    });
  });
});

describe('authorize', () => {
  it('returns one refusal for every reason and a missing target', () => {
    const { service } = createHarness();

    const ownerTarget = service.authorize(AccessAction.USER_BLOCK, ADMIN, OWNER);
    const selfAction = service.authorize(AccessAction.USER_BLOCK, ADMIN, {
      id: ADMIN_ID,
      role: Role.ADMIN,
    });
    const adminPeer = service.authorize(AccessAction.USER_BLOCK, ADMIN, {
      id: PEER_ADMIN_ID,
      role: Role.ADMIN,
    });
    const missing = service.authorize(AccessAction.USER_BLOCK, ADMIN, null);

    expect(ownerTarget).toBe(selfAction);
    expect(selfAction).toBe(adminPeer);
    expect(adminPeer).toBe(missing);
    expect(ownerTarget).toEqual({ allowed: false });
    expect(Object.keys(ownerTarget)).toEqual(['allowed']);
  });

  it('allows an admin to moderate a regular account', () => {
    const { service } = createHarness();

    expect(service.authorize(AccessAction.USER_BLOCK, ADMIN, MEMBER)).toEqual({ allowed: true });
    expect(service.authorize(AccessAction.ADMIN_GRANT, OWNER, MEMBER)).toEqual({ allowed: true });
  });
});

describe('recordSuccess', () => {
  it('writes the row without contact data', async () => {
    const { service, audit } = createHarness();

    await service.recordSuccess(ADMIN_AUDIT_ACTIONS.USER_BLOCK, ADMIN_ID, USER_ID, REQUEST_ID, {
      from: 'ACTIVE',
      to: 'BLOCKED',
    });

    expect(audit.records).toHaveLength(1);
    expect(audit.records[0]).toMatchObject({
      action: 'admin.user.block',
      actorId: ADMIN_ID,
      targetType: 'user',
      targetId: USER_ID,
      requestId: REQUEST_ID,
      metadata: { from: 'ACTIVE', to: 'BLOCKED' },
    });
    expect(JSON.stringify(audit.records)).not.toContain(PHONE);
    expect(JSON.stringify(audit.records)).not.toContain(USERNAME);
  });

  it('fails the action when the row cannot be written', async () => {
    const { service, audit, logger } = createHarness(new FailingAudit());

    await expect(
      service.recordSuccess(ADMIN_AUDIT_ACTIONS.ADMIN_GRANT, OWNER_ID, USER_ID, REQUEST_ID),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(audit.records).toHaveLength(1);
    expect(logger.warns).toHaveLength(1);
    expect(logger.warns[0]?.payload).toEqual({
      requestId: REQUEST_ID,
      action: 'admin.admin.grant',
    });
    expect(JSON.stringify(logger.warns)).not.toContain(PHONE);
    expect(JSON.stringify(logger.warns)).not.toContain(USER_ID);
  });
});

describe('revokeAllSessionsOrFail', () => {
  it('revokes through the shared repository method', async () => {
    const sessions = new RecordingSessions();
    const { service } = createHarness(new FakeAudit(), sessions);

    await service.revokeAllSessionsOrFail(USER_ID);

    expect(sessions.revokedAll).toEqual([{ userId: USER_ID, reason: 'admin_action' }]);
  });

  it('surfaces a failed revocation', async () => {
    const { service } = createHarness(new FakeAudit(), new FailingSessions());

    await expect(service.revokeAllSessionsOrFail(USER_ID)).rejects.toThrow(
      'sessions are unavailable',
    );
  });
});

describe('LogOwnerNotifier', () => {
  it('writes one line without contact data', async () => {
    const logger = new RecordingLogger();
    const notifier = new LogOwnerNotifier(logger as unknown as PinoLogger);

    await notifier.notifyAdminGranted({
      actorId: OWNER_ID,
      targetId: USER_ID,
      at: new Date('2026-03-01T00:00:00.000Z'),
    });

    expect(logger.infos).toHaveLength(1);
    expect(logger.infos[0]?.payload).toEqual({
      actorId: OWNER_ID,
      targetId: USER_ID,
      at: '2026-03-01T00:00:00.000Z',
    });

    const logged = JSON.stringify(logger.infos);

    expect(logged).not.toContain(PHONE);
    expect(logged).not.toContain(USERNAME);
  });
});
