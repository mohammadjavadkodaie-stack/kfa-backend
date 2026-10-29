import { ForbiddenException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import { Role } from '../roles';
import { AccessAction, type PolicySubject } from './access-policy';
import { AccessPolicyService, type AccessPolicyContext } from './access-policy.service';

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const OWNER_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '33333333-3333-4333-8333-333333333333';
/** Never passed to the service; proves the trail stays free of contact data. */
const PHONE = '+14155550123';

const CONTEXT: AccessPolicyContext = { requestId: 'req-policy', ip: '203.0.113.7' };

const owner: PolicySubject = { id: OWNER_ID, role: Role.OWNER };
const admin: PolicySubject = { id: ADMIN_ID, role: Role.ADMIN };
const user: PolicySubject = { id: USER_ID, role: Role.USER };

interface WarnCall {
  readonly payload: Record<string, unknown>;
  readonly message: unknown;
}

class RecordingLogger {
  readonly warns: WarnCall[] = [];

  warn(payload: Record<string, unknown>, message?: unknown): void {
    this.warns.push({ payload, message });
  }
}

/** An audit trail that cannot be written: the refusal must survive it. */
class FailingAudit extends FakeAudit {
  override async record(entry: AuditRecord): Promise<void> {
    await super.record(entry);

    throw new Error('audit chain is unavailable');
  }
}

function createService(audit: FakeAudit = new FakeAudit()) {
  const logger = new RecordingLogger();
  const service = new AccessPolicyService(
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, audit, logger };
}

/** The exception a refused call threw, or a failure when it was not refused. */
async function refusalOf(call: Promise<unknown>): Promise<ForbiddenException> {
  try {
    await call;
  } catch (error) {
    if (error instanceof ForbiddenException) return error;

    throw error;
  }

  throw new Error('expected the call to be refused');
}

function onlyRecord(audit: FakeAudit): AuditRecord {
  expect(audit.records).toHaveLength(1);

  const record = audit.records[0];

  if (record === undefined) throw new Error('no audit record');

  return record;
}

describe('AccessPolicyService: allowed calls', () => {
  it('returns normally and writes nothing when the action is allowed', async () => {
    const { service, audit } = createService();

    await service.authorize(admin, { action: AccessAction.USER_BLOCK }, user, CONTEXT);
    await service.authorize(owner, { action: AccessAction.ADMIN_GRANT }, user, CONTEXT);
    await service.authorize(
      owner,
      { action: AccessAction.USER_CHANGE_ROLE, role: Role.ATHLETE },
      user,
      CONTEXT,
    );

    expect(audit.records).toHaveLength(0);
  });
});

describe('AccessPolicyService: refused staff actions are audited once', () => {
  it('records one authz.denied row with exactly the four allowed metadata keys', async () => {
    const { service, audit } = createService();
    const refusal = await refusalOf(
      service.authorize(admin, { action: AccessAction.USER_BLOCK }, owner, CONTEXT),
    );

    expect(refusal.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden' });

    const record = onlyRecord(audit);

    expect(record).toMatchObject({
      action: 'authz.denied',
      actorId: ADMIN_ID,
      actorRole: 'ADMIN',
      targetType: 'user',
      targetId: OWNER_ID,
      requestId: 'req-policy',
      ip: '203.0.113.7',
    });
    expect(Object.keys(record.metadata).sort()).toEqual([
      'action',
      'actorRole',
      'targetId',
      'targetRole',
    ]);
    expect(record.metadata).toEqual({
      actorRole: 'ADMIN',
      action: 'user.block',
      targetId: OWNER_ID,
      targetRole: 'OWNER',
    });
    expect(Object.values(record.metadata)).toHaveLength(4);
    expect(JSON.stringify(record.metadata)).not.toContain(PHONE);
    expect(JSON.stringify(record.metadata)).not.toMatch(/\+\d{7,}/);
  });

  it('records a refused OWNER action too', async () => {
    const { service, audit } = createService();

    await refusalOf(service.authorize(owner, { action: AccessAction.OWNER_GRANT }, admin, CONTEXT));

    const record = onlyRecord(audit);

    expect(record.actorId).toBe(OWNER_ID);
    expect(record.actorRole).toBe('OWNER');
    expect(record.metadata).toEqual({
      actorRole: 'OWNER',
      action: 'owner.grant',
      targetId: ADMIN_ID,
      targetRole: 'ADMIN',
    });
  });

  it('never stores an action or a role that is outside the closed set', async () => {
    const { service, audit } = createService();

    await refusalOf(service.authorize(admin, { action: 'user.explode\r\n' }, user, CONTEXT));
    await refusalOf(
      service.authorize(
        owner,
        { action: AccessAction.USER_BLOCK },
        { id: USER_ID, role: 'SUPERUSER' as Role },
        CONTEXT,
      ),
    );

    const [first, second] = audit.records;

    expect(first?.metadata).toEqual({
      actorRole: 'ADMIN',
      action: 'unknown',
      targetId: USER_ID,
      targetRole: 'USER',
    });
    expect(second?.metadata).toEqual({
      actorRole: 'OWNER',
      action: 'user.block',
      targetId: USER_ID,
      targetRole: 'unknown',
    });
  });

  it('does not audit a refused USER or ATHLETE actor', async () => {
    const { service, audit } = createService();

    for (const role of [Role.USER, Role.ATHLETE]) {
      const refusal = await refusalOf(
        service.authorize(
          { id: USER_ID, role },
          { action: AccessAction.USER_BLOCK },
          user,
          CONTEXT,
        ),
      );

      expect(refusal.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden' });
    }

    expect(audit.records).toHaveLength(0);
  });
});

describe('AccessPolicyService: every refusal looks the same', () => {
  it('answers the identical generic 403 for every kind of denial', async () => {
    const { service } = createService();
    const bodies: unknown[] = [];

    const capture = async (call: Promise<unknown>): Promise<void> => {
      bodies.push((await refusalOf(call)).getResponse());
    };

    await capture(service.authorize(admin, { action: AccessAction.USER_BLOCK }, owner, CONTEXT));
    await capture(
      service.authorize(
        admin,
        { action: AccessAction.USER_BLOCK },
        { id: ADMIN_ID, role: Role.ADMIN },
        CONTEXT,
      ),
    );
    await capture(service.authorize(admin, { action: 'user.explode' }, user, CONTEXT));
    await capture(service.authorize(admin, { action: AccessAction.ADMIN_GRANT }, user, CONTEXT));
    await capture(
      service.authorize(
        owner,
        { action: AccessAction.USER_CHANGE_ROLE, role: Role.OWNER },
        user,
        CONTEXT,
      ),
    );
    await capture(
      service.authorize(
        owner,
        { action: AccessAction.USER_CHANGE_ROLE, role: Role.USER },
        user,
        CONTEXT,
      ),
    );
    await capture(
      service.authorize(owner, { action: AccessAction.USER_CHANGE_ROLE }, user, CONTEXT),
    );
    await capture(
      service.authorize(
        { id: USER_ID, role: 'SUPERUSER' as Role },
        { action: AccessAction.USER_BLOCK },
        user,
        CONTEXT,
      ),
    );

    expect(bodies).toHaveLength(8);

    for (const body of bodies) {
      expect(body).toEqual({ statusCode: 403, message: 'Forbidden' });
    }

    // No internal code may ever reach the client.
    expect(JSON.stringify(bodies)).not.toMatch(
      /self_action|target_is_owner|admin_|owner_grant|unknown_|target_already|target_not_admin/,
    );
  });
});

describe('AccessPolicyService: a failed audit never widens the answer', () => {
  it('still refuses with the same 403 and logs no request data', async () => {
    const { service, audit, logger } = createService(new FailingAudit());

    const refusal = await refusalOf(
      service.authorize(admin, { action: AccessAction.USER_BLOCK }, owner, CONTEXT),
    );

    expect(refusal.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(audit.records).toHaveLength(1);

    const failure = logger.warns.find((call) => call.message === 'authz audit failed');

    expect(failure).toBeDefined();
    expect(Object.keys(failure?.payload ?? {}).sort()).toEqual(['action', 'reason', 'requestId']);

    const logged = JSON.stringify(failure);

    expect(logged).not.toContain(ADMIN_ID);
    expect(logged).not.toContain(OWNER_ID);
    expect(logged).not.toContain(PHONE);
    expect(logged).not.toContain('audit chain is unavailable');
  });

  it('logs the internal denial reason, and nothing else, for a refused staff action', async () => {
    const { service, logger } = createService();

    await refusalOf(service.authorize(admin, { action: AccessAction.USER_BLOCK }, owner, CONTEXT));

    expect(logger.warns).toHaveLength(1);
    expect(logger.warns[0]?.payload).toEqual({
      requestId: 'req-policy',
      reason: 'target_is_owner',
      action: 'authz.denied',
    });
    expect(logger.warns[0]?.message).toBe('access denied');
  });
});
