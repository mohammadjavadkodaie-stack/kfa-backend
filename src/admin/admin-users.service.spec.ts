import {
  HttpException,
  InternalServerErrorException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../test/helpers/auth-service-harness';
import type { AuditService } from '../audit/audit.service';
import { InMemorySessionRepository } from '../auth/in-memory-session.repository';
import { AccessAction, type PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { InMemoryTotpRepository } from '../auth/totp/in-memory-totp.repository';
import { ADMIN_AUDIT_ACTIONS, AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier, type AdminGrantedNotice, type OwnerNotifier } from './owner-notifier';

const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const ADMIN_ID = '22222222-2222-4222-8222-222222222222';
const PEER_ADMIN_ID = '33333333-3333-4333-8333-333333333333';
const USER_ID = '44444444-4444-4444-8444-444444444444';
const UNKNOWN_ID = '55555555-5555-4555-8555-555555555555';
const ATHLETE_ID = '66666666-6666-4666-8666-666666666666';
const BLOCKED_ID = '77777777-7777-4777-8777-777777777777';
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

/** Keeps what the owner would receive, so a spec can prove ids are all it holds. */
class RecordingNotifier implements OwnerNotifier {
  readonly notices: AdminGrantedNotice[] = [];

  async notifyAdminGranted(notice: AdminGrantedNotice): Promise<void> {
    this.notices.push(notice);
  }
}

class FailingNotifier implements OwnerNotifier {
  calls = 0;

  async notifyAdminGranted(): Promise<void> {
    this.calls += 1;

    throw new Error('the messaging gateway is unavailable');
  }
}

/** Fails the first revocation, so a retry has to finish the job. */
class FlakySessions extends InMemorySessionRepository {
  revocations = 0;

  override async revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void> {
    this.revocations += 1;

    if (this.revocations === 1) throw new Error('sessions are unavailable');

    return super.revokeAllUserSessions(userId, reason, now);
  }
}

/** Loses the compare-and-set: a parallel request demoted the row first. */
class LosingSessions extends InMemorySessionRepository {
  override async setRoleIf(userId: string, expectedRole: Role, newRole: Role): Promise<boolean> {
    const user = this.users.get(userId);

    if (user?.role === expectedRole) user.role = newRole;

    return false;
  }
}

function createHarness(
  audit: FakeAudit = new FakeAudit(),
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
  notifier: OwnerNotifier = new LogOwnerNotifier(new RecordingLogger() as unknown as PinoLogger),
  totp: InMemoryTotpRepository = new InMemoryTotpRepository(),
) {
  const policy = new AccessPolicyService(
    audit as unknown as AuditService,
    new RecordingLogger() as unknown as PinoLogger,
  );
  const logger = new RecordingLogger();
  const service = new AdminUsersService(
    sessions,
    totp,
    policy,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
    notifier,
  );

  return { service, sessions, audit, logger, notifier, totp };
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

/** What a refused call looks like from outside: a status and a generic body. */
async function refusal(run: () => Promise<void>): Promise<{ status: number; body: unknown }> {
  try {
    await run();
  } catch (error) {
    if (error instanceof HttpException) {
      return { status: error.getStatus(), body: error.getResponse() };
    }

    throw error;
  }

  throw new Error('the call was expected to be refused');
}

function seed(sessions: InMemorySessionRepository): void {
  sessions.seedUser({ id: OWNER_ID, phone: '+14155550100', username: 'owner', role: Role.OWNER });
  sessions.seedUser({ id: ADMIN_ID, phone: '+14155550101', username: 'admin', role: Role.ADMIN });
  sessions.seedUser({ id: USER_ID, phone: '+14155550102', username: 'ivan', role: Role.USER });
}

function moderationHarness(
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
  audit: FakeAudit = new FakeAudit(),
) {
  seed(sessions);

  return createHarness(audit, sessions);
}

async function giveSessions(
  sessions: InMemorySessionRepository,
  userId: string,
  count: number,
): Promise<void> {
  const now = new Date();

  for (let index = 0; index < count; index += 1) {
    await sessions.createSession({
      userId,
      deviceKeyHash: `device-${index}`,
      deviceBound: true,
      deviceLabel: null,
      now,
      sessionExpiresAt: new Date(now.getTime() + 3_600_000),
      refreshTokenHash: `hash-${index}`,
      refreshExpiresAt: new Date(now.getTime() + 3_600_000),
      maxActiveSessions: 10,
    });
  }
}

function grantHarness(
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
  audit: FakeAudit = new FakeAudit(),
  notifier: OwnerNotifier = new RecordingNotifier(),
) {
  seed(sessions);
  sessions.seedUser({
    id: ATHLETE_ID,
    phone: '+14155550103',
    username: 'olga',
    role: Role.ATHLETE,
  });
  sessions.seedUser({
    id: BLOCKED_ID,
    phone: '+14155550104',
    username: 'pavel',
    role: Role.USER,
    status: 'BLOCKED',
  });

  return createHarness(audit, sessions, notifier);
}

function revokeHarness(
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
  audit: FakeAudit = new FakeAudit(),
) {
  seed(sessions);
  sessions.seedUser({
    id: PEER_ADMIN_ID,
    phone: '+14155550105',
    username: 'boris',
    role: Role.ADMIN,
  });

  return createHarness(audit, sessions);
}

describe('block', () => {
  it('lets an owner and an admin block a normal account', async () => {
    for (const actor of [OWNER, ADMIN]) {
      const { service, sessions, audit } = moderationHarness();

      await service.block(actor, USER_ID, REQUEST_ID);

      expect(sessions.users.get(USER_ID)?.status).toBe('BLOCKED');
      expect(audit.records.map((row) => row.action)).toEqual(['admin.user.block']);
    }
  });

  it('cuts every session of the target', async () => {
    const { service, sessions } = moderationHarness();

    await giveSessions(sessions, USER_ID, 2);

    await service.block(ADMIN, USER_ID, REQUEST_ID);

    expect(await sessions.listActiveSessions(USER_ID, new Date())).toEqual([]);
  });

  it('refuses an admin blocking the owner', async () => {
    const { service, sessions, audit } = moderationHarness();

    const refused = await refusal(() => service.block(ADMIN, OWNER_ID, REQUEST_ID));

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(sessions.users.get(OWNER_ID)?.status).toBe('ACTIVE');
    expect(audit.records).toHaveLength(0);
  });

  it('refuses blocking oneself', async () => {
    const { service } = moderationHarness();

    expect((await refusal(() => service.block(ADMIN, ADMIN_ID, REQUEST_ID))).status).toBe(403);
  });

  it('answers a malformed id exactly like an unknown one', async () => {
    const { service } = moderationHarness();

    const unknown = await refusal(() => service.block(ADMIN, UNKNOWN_ID, REQUEST_ID));
    const malformed = await refusal(() => service.block(ADMIN, 'not-a-uuid', REQUEST_ID));

    expect(unknown.status).toBe(404);
    expect(unknown).toEqual(malformed);
  });

  it('blocks an already blocked account once and revokes again', async () => {
    const sessions = new RecordingSessions();
    const { service, audit } = moderationHarness(sessions);

    await service.block(ADMIN, USER_ID, REQUEST_ID);
    await service.block(ADMIN, USER_ID, REQUEST_ID);

    expect(sessions.users.get(USER_ID)?.status).toBe('BLOCKED');
    expect(sessions.revokedAll).toHaveLength(2);
    expect(audit.records).toHaveLength(1);
  });

  it('reports a failed revocation as a generic 500 without a success row', async () => {
    const sessions = new FailingSessions();
    const { service, audit } = moderationHarness(sessions);

    const failed = await refusal(() => service.block(ADMIN, USER_ID, REQUEST_ID));

    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ statusCode: 500, message: 'Internal Server Error' });
    // No rollback: the block stands and the next attempt finishes the revocation.
    expect(sessions.users.get(USER_ID)?.status).toBe('BLOCKED');
    expect(audit.records).toHaveLength(0);
  });

  it('does not report success when the audit row cannot be written', async () => {
    const { service, audit } = moderationHarness(
      new InMemorySessionRepository(),
      new FailingAudit(),
    );

    await expect(service.block(ADMIN, USER_ID, REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(audit.records).toHaveLength(1);
  });
});

describe('unblock', () => {
  it('lets an owner and an admin unblock an account', async () => {
    for (const actor of [OWNER, ADMIN]) {
      const { service, sessions, audit } = moderationHarness();

      await service.block(ADMIN, USER_ID, REQUEST_ID);
      await service.unblock(actor, USER_ID, REQUEST_ID);

      expect(sessions.users.get(USER_ID)?.status).toBe('ACTIVE');
      expect(audit.records.map((row) => row.action)).toEqual([
        'admin.user.block',
        'admin.user.unblock',
      ]);
    }
  });

  it('does not restore the sessions that were cut', async () => {
    const { service, sessions } = moderationHarness();

    await giveSessions(sessions, USER_ID, 1);
    await service.block(ADMIN, USER_ID, REQUEST_ID);
    await service.unblock(ADMIN, USER_ID, REQUEST_ID);

    expect(await sessions.listActiveSessions(USER_ID, new Date())).toEqual([]);
  });

  it('refuses unblocking the owner and oneself', async () => {
    const { service } = moderationHarness();

    expect((await refusal(() => service.unblock(ADMIN, OWNER_ID, REQUEST_ID))).status).toBe(403);
    expect((await refusal(() => service.unblock(ADMIN, ADMIN_ID, REQUEST_ID))).status).toBe(403);
  });

  it('records the transition once', async () => {
    const { service, audit } = moderationHarness();

    await service.block(ADMIN, USER_ID, REQUEST_ID);
    await service.unblock(ADMIN, USER_ID, REQUEST_ID);
    await service.unblock(ADMIN, USER_ID, REQUEST_ID);

    expect(audit.records.map((row) => row.action)).toEqual([
      'admin.user.block',
      'admin.user.unblock',
    ]);
  });
});

describe('grant admin', () => {
  it('promotes an active user and an active athlete', async () => {
    for (const [id, from] of [
      [USER_ID, Role.USER],
      [ATHLETE_ID, Role.ATHLETE],
    ] as const) {
      const { service, sessions, audit } = grantHarness();

      await service.grantAdmin(OWNER, id, REQUEST_ID);

      expect(sessions.users.get(id)?.role).toBe(Role.ADMIN);
      expect(audit.records.map((row) => row.action)).toEqual([ADMIN_AUDIT_ACTIONS.ADMIN_GRANT]);
      expect(audit.records[0]?.metadata).toEqual({ from, to: Role.ADMIN, notified: true });
    }
  });

  it('refuses an admin actor', async () => {
    const { service, sessions, audit } = grantHarness();

    const refused = await refusal(() => service.grantAdmin(ADMIN, USER_ID, REQUEST_ID));

    expect(refused.status).toBe(403);
    expect(refused.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(sessions.users.get(USER_ID)?.role).toBe(Role.USER);
    expect(audit.records).toHaveLength(0);
  });

  it('refuses the owner as a target', async () => {
    const { service, sessions, audit } = grantHarness();

    const refused = await refusal(() => service.grantAdmin(OWNER, OWNER_ID, REQUEST_ID));

    expect(refused.status).toBe(403);
    expect(sessions.users.get(OWNER_ID)?.role).toBe(Role.OWNER);
    expect(audit.records).toHaveLength(0);
  });

  it('answers a blocked target like any other refusal', async () => {
    const { service, sessions } = grantHarness();

    const blocked = await refusal(() => service.grantAdmin(OWNER, BLOCKED_ID, REQUEST_ID));
    const notAnOwner = await refusal(() => service.grantAdmin(ADMIN, USER_ID, REQUEST_ID));

    expect(blocked.status).toBe(403);
    expect(blocked).toEqual(notAnOwner);
    expect(sessions.users.get(BLOCKED_ID)?.role).toBe(Role.USER);
  });

  it('answers an unknown or malformed id as not found', async () => {
    const { service } = grantHarness();

    const unknown = await refusal(() => service.grantAdmin(OWNER, UNKNOWN_ID, REQUEST_ID));
    const malformed = await refusal(() => service.grantAdmin(OWNER, 'not-a-uuid', REQUEST_ID));

    expect(unknown.status).toBe(404);
    expect(unknown).toEqual(malformed);
  });

  it('records nothing for a target that is already an admin', async () => {
    const notifier = new RecordingNotifier();
    const sessions = new RecordingSessions();
    const { service, audit } = grantHarness(sessions, new FakeAudit(), notifier);

    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);
    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);

    expect(sessions.users.get(USER_ID)?.role).toBe(Role.ADMIN);
    // A retry only repeats the revocation of the grant that was already made.
    expect(sessions.revokedAll).toHaveLength(2);
    expect(audit.records).toHaveLength(1);
    expect(notifier.notices).toHaveLength(1);
  });

  it('cuts every session of the target', async () => {
    const sessions = new InMemorySessionRepository();
    const { service } = grantHarness(sessions);

    await giveSessions(sessions, USER_ID, 2);
    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);

    expect(await sessions.listActiveSessions(USER_ID, new Date())).toEqual([]);
  });

  it('tells the owner once, with ids only', async () => {
    const notifier = new RecordingNotifier();
    const { service } = grantHarness(new InMemorySessionRepository(), new FakeAudit(), notifier);

    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);

    expect(notifier.notices).toHaveLength(1);

    const notice = notifier.notices[0];

    expect(notice).toEqual({ actorId: OWNER_ID, targetId: USER_ID, at: expect.any(Date) });
    expect(Object.keys(notice ?? {}).sort()).toEqual(['actorId', 'at', 'targetId']);
    expect(JSON.stringify(notice)).not.toContain(USERNAME);
    expect(JSON.stringify(notice)).not.toContain('+14155550102');
  });

  it('keeps the grant when the notification fails', async () => {
    const notifier = new FailingNotifier();
    const { service, sessions, audit, logger } = grantHarness(
      new InMemorySessionRepository(),
      new FakeAudit(),
      notifier,
    );

    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);

    expect(notifier.calls).toBe(1);
    expect(sessions.users.get(USER_ID)?.role).toBe(Role.ADMIN);
    expect(audit.records[0]?.metadata).toEqual({
      from: Role.USER,
      to: Role.ADMIN,
      notified: false,
    });
    expect(logger.warns.map((call) => call.message)).toEqual(['owner notify failed']);
  });

  it('reports a failed revocation as a generic 500 without a success row', async () => {
    const { service, sessions, audit } = grantHarness(
      new FailingSessions(),
      new FakeAudit(),
      new RecordingNotifier(),
    );

    const failed = await refusal(() => service.grantAdmin(OWNER, USER_ID, REQUEST_ID));

    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ statusCode: 500, message: 'Internal Server Error' });
    // No rollback: the role change stands and the next attempt finishes the job.
    expect(sessions.users.get(USER_ID)?.role).toBe(Role.ADMIN);
    expect(audit.records).toHaveLength(0);
  });

  it('finishes an interrupted grant on the next attempt', async () => {
    const notifier = new RecordingNotifier();
    const sessions = new FlakySessions();
    const { service, audit } = grantHarness(sessions, new FakeAudit(), notifier);

    await giveSessions(sessions, USER_ID, 1);
    await expect(service.grantAdmin(OWNER, USER_ID, REQUEST_ID)).rejects.toBeInstanceOf(
      InternalServerErrorException,
    );

    await service.grantAdmin(OWNER, USER_ID, REQUEST_ID);

    expect(sessions.revocations).toBe(2);
    expect(await sessions.listActiveSessions(USER_ID, new Date())).toEqual([]);
    // The interrupted attempt recorded nothing, the retry has nothing new to add.
    expect(audit.records).toHaveLength(0);
    expect(notifier.notices).toHaveLength(0);
  });

  it('does not report success when the audit row cannot be written', async () => {
    const { service, sessions, audit } = grantHarness(
      new InMemorySessionRepository(),
      new FailingAudit(),
      new RecordingNotifier(),
    );

    await expect(service.grantAdmin(OWNER, USER_ID, REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(sessions.users.get(USER_ID)?.role).toBe(Role.ADMIN);
    expect(audit.records).toHaveLength(1);
  });
});

describe('revoke admin', () => {
  it('demotes an admin to the base role', async () => {
    const { service, sessions, audit } = revokeHarness();

    await service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID);

    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.USER);
    expect(audit.records.map((row) => row.action)).toEqual([ADMIN_AUDIT_ACTIONS.ADMIN_REVOKE]);
    expect(audit.records[0]?.metadata).toEqual({ from: Role.ADMIN, to: Role.USER });
  });

  it('leaves the rest of the account alone', async () => {
    const { service, sessions } = revokeHarness();

    sessions.setUserRole(ADMIN_ID, { identityVerifier: true });

    await service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID);

    // The verifier flag and the second factor are separate permissions.
    expect(sessions.users.get(ADMIN_ID)).toMatchObject({
      role: Role.USER,
      status: 'ACTIVE',
      identityVerifier: true,
    });
  });

  it('refuses an admin actor on a peer and on itself', async () => {
    const { service, sessions, audit } = revokeHarness();

    const peer = await refusal(() => service.revokeAdmin(ADMIN, PEER_ADMIN_ID, REQUEST_ID));
    const self = await refusal(() => service.revokeAdmin(ADMIN, ADMIN_ID, REQUEST_ID));

    expect(peer.status).toBe(403);
    expect(peer.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(self).toEqual(peer);
    expect(sessions.users.get(PEER_ADMIN_ID)?.role).toBe(Role.ADMIN);
    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.ADMIN);
    expect(audit.records).toHaveLength(0);
  });

  it('refuses the owner as a target', async () => {
    const { service, sessions, audit } = revokeHarness();

    const refused = await refusal(() => service.revokeAdmin(OWNER, OWNER_ID, REQUEST_ID));

    expect(refused.status).toBe(403);
    expect(sessions.users.get(OWNER_ID)?.role).toBe(Role.OWNER);
    expect(sessions.users.get(OWNER_ID)?.status).toBe('ACTIVE');
    expect(audit.records).toHaveLength(0);
  });

  it('answers a user target and an unknown id alike', async () => {
    const { service, sessions, audit } = revokeHarness();

    const target = await refusal(() => service.revokeAdmin(OWNER, USER_ID, REQUEST_ID));
    const unknown = await refusal(() => service.revokeAdmin(OWNER, UNKNOWN_ID, REQUEST_ID));
    const malformed = await refusal(() => service.revokeAdmin(OWNER, 'not-a-uuid', REQUEST_ID));

    expect(target.status).toBe(403);
    expect(target.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(unknown).toEqual(target);
    expect(malformed).toEqual(target);
    expect(sessions.users.get(USER_ID)?.role).toBe(Role.USER);
    expect(audit.records).toHaveLength(0);
  });

  it('cuts every session of the target', async () => {
    const sessions = new InMemorySessionRepository();
    const { service } = revokeHarness(sessions);

    await giveSessions(sessions, ADMIN_ID, 2);

    await service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID);

    expect(await sessions.listActiveSessions(ADMIN_ID, new Date())).toEqual([]);
  });

  it('reports a failed revocation as a generic 500 without a success row', async () => {
    const { service, sessions, audit } = revokeHarness(new FailingSessions());

    const failed = await refusal(() => service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID));

    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ statusCode: 500, message: 'Internal Server Error' });
    // No rollback: the demotion stands and nothing claims a finished revoke.
    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.USER);
    expect(audit.records).toHaveLength(0);
  });

  it('does not report success when the audit row cannot be written', async () => {
    const { service, sessions, audit } = revokeHarness(
      new InMemorySessionRepository(),
      new FailingAudit(),
    );

    await expect(service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.USER);
    expect(audit.records).toHaveLength(1);
  });

  it('answers a repeated revoke alike and records once', async () => {
    const sessions = new RecordingSessions();
    const { service, audit } = revokeHarness(sessions);

    await service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID);

    const repeated = await refusal(() => service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID));

    // The demoted account keeps its role, and only the first call recorded it.
    expect(repeated.status).toBe(403);
    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.USER);
    expect(sessions.revokedAll).toHaveLength(1);
    expect(audit.records).toHaveLength(1);
  });

  it('repeats the revocation when a parallel revoke demoted first', async () => {
    const sessions = new LosingSessions();
    const { service, audit } = revokeHarness(sessions);

    await giveSessions(sessions, ADMIN_ID, 1);

    await service.revokeAdmin(OWNER, ADMIN_ID, REQUEST_ID);

    // The demotion was somebody else's; the revocation is still ours to finish.
    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.USER);
    expect(await sessions.listActiveSessions(ADMIN_ID, new Date())).toEqual([]);
    expect(audit.records).toHaveLength(0);
  });
});

/** A confirmed factor with two unused codes: what a reset has to remove. */
function seedFactor(totp: InMemoryTotpRepository, userId: string): void {
  totp.credentials.set(userId, {
    secretEnc: 'test-envelope',
    confirmedAt: new Date(),
    lastUsedStep: 1,
  });
  totp.recoveryCodes.set(userId, [
    { codeHash: 'hash-one', usedAt: null },
    { codeHash: 'hash-two', usedAt: null },
  ]);
}

function resetHarness(
  sessions: InMemorySessionRepository = new InMemorySessionRepository(),
  audit: FakeAudit = new FakeAudit(),
  totp: InMemoryTotpRepository = new InMemoryTotpRepository(),
) {
  seed(sessions);
  sessions.seedUser({
    id: PEER_ADMIN_ID,
    phone: '+14155550105',
    username: 'boris',
    role: Role.ADMIN,
  });

  return createHarness(audit, sessions, undefined, totp);
}

describe('resetTotp', () => {
  it('lets the owner clear the factor of an admin', async () => {
    const { service, sessions, audit, totp } = resetHarness();

    seedFactor(totp, ADMIN_ID);
    await giveSessions(sessions, ADMIN_ID, 2);

    await service.resetTotp(OWNER, ADMIN_ID, REQUEST_ID);

    expect(totp.credentials.has(ADMIN_ID)).toBe(false);
    expect(totp.recoveryCodes.has(ADMIN_ID)).toBe(false);
    expect(await sessions.listActiveSessions(ADMIN_ID, new Date())).toEqual([]);
    // The role is untouched: the gate, not a demotion, keeps the target out.
    expect(sessions.users.get(ADMIN_ID)?.role).toBe(Role.ADMIN);
    expect(audit.records.map((row) => row.action)).toEqual([ADMIN_AUDIT_ACTIONS.TOTP_RESET]);
    expect(audit.records[0]?.metadata).toEqual({ role: Role.ADMIN });
  });

  it('refuses an admin actor on a peer and on itself', async () => {
    const { service, audit, totp } = resetHarness();

    seedFactor(totp, ADMIN_ID);
    seedFactor(totp, PEER_ADMIN_ID);

    const self = await refusal(() => service.resetTotp(ADMIN, ADMIN_ID, REQUEST_ID));
    const peer = await refusal(() => service.resetTotp(ADMIN, PEER_ADMIN_ID, REQUEST_ID));

    expect(self.status).toBe(403);
    expect(self.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(peer).toEqual(self);
    expect(totp.credentials.size).toBe(2);
    expect(audit.records).toHaveLength(0);
  });

  it('answers the owner, a user and an unknown id alike', async () => {
    const { service, sessions, audit, totp } = resetHarness();

    seedFactor(totp, ADMIN_ID);

    const ownerTarget = await refusal(() => service.resetTotp(OWNER, OWNER_ID, REQUEST_ID));
    const memberTarget = await refusal(() => service.resetTotp(OWNER, USER_ID, REQUEST_ID));
    const unknown = await refusal(() => service.resetTotp(OWNER, UNKNOWN_ID, REQUEST_ID));
    const malformed = await refusal(() => service.resetTotp(OWNER, 'not-a-uuid', REQUEST_ID));

    expect(ownerTarget.status).toBe(403);
    expect(ownerTarget.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(memberTarget).toEqual(ownerTarget);
    expect(unknown).toEqual(ownerTarget);
    expect(malformed).toEqual(ownerTarget);
    expect(sessions.users.get(OWNER_ID)?.role).toBe(Role.OWNER);
    expect(totp.credentials.has(ADMIN_ID)).toBe(true);
    expect(audit.records).toHaveLength(0);
  });

  it('reports a failed revocation as a generic 500 without a success row', async () => {
    const sessions = new FailingSessions();
    const { service, audit, totp } = resetHarness(sessions);

    seedFactor(totp, ADMIN_ID);

    const failed = await refusal(() => service.resetTotp(OWNER, ADMIN_ID, REQUEST_ID));

    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ statusCode: 500, message: 'Internal Server Error' });
    // No rollback: the factor is gone, and only the revocation is left to retry.
    expect(totp.credentials.has(ADMIN_ID)).toBe(false);
    expect(audit.records).toHaveLength(0);
  });

  it('does not report success when the audit row cannot be written', async () => {
    const { service, audit, totp } = resetHarness(undefined, new FailingAudit());

    seedFactor(totp, ADMIN_ID);

    await expect(service.resetTotp(OWNER, ADMIN_ID, REQUEST_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(totp.credentials.has(ADMIN_ID)).toBe(false);
    expect(audit.records).toHaveLength(1);
  });

  it('answers a repeated reset alike and records once', async () => {
    const sessions = new RecordingSessions();
    const { service, audit, totp } = resetHarness(sessions);

    seedFactor(totp, ADMIN_ID);

    await service.resetTotp(OWNER, ADMIN_ID, REQUEST_ID);
    await service.resetTotp(OWNER, ADMIN_ID, REQUEST_ID);

    // The second call still revokes, but there is no second change to record.
    expect(sessions.revokedAll).toEqual([
      { userId: ADMIN_ID, reason: 'admin_action' },
      { userId: ADMIN_ID, reason: 'admin_action' },
    ]);
    expect(audit.records).toHaveLength(1);
  });
});
