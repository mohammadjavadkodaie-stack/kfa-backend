import { ForbiddenException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import { Role } from '../roles';
import type { PolicySubject } from './access-policy';
import type { AccessPolicyContext } from './access-policy.service';
import { ResourceOwnershipService } from './resource-ownership.service';

const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '22222222-2222-4222-8222-222222222222';
const ADMIN_ID = '33333333-3333-4333-8333-333333333333';

const CONTEXT: AccessPolicyContext = { requestId: 'req-ownership', ip: '203.0.113.7' };

const owner: PolicySubject = { id: OWNER_ID, role: Role.USER };
const other: PolicySubject = { id: OTHER_ID, role: Role.USER };

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

/** A trail that cannot be written: the refusal must survive it. */
class FailingAudit extends FakeAudit {
  override async record(entry: AuditRecord): Promise<void> {
    await super.record(entry);

    throw new Error('audit chain is unavailable');
  }
}

function createService(audit: FakeAudit = new FakeAudit()) {
  const logger = new RecordingLogger();
  const service = new ResourceOwnershipService(
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

describe('ResourceOwnershipService', () => {
  it('allows the owner', async () => {
    const { service, audit } = createService();

    await expect(service.assertOwnsResource(owner, OWNER_ID, CONTEXT)).resolves.toBeUndefined();
    expect(audit.records).toHaveLength(0);
  });

  it('refuses another user with the generic 403', async () => {
    const { service } = createService();
    const refusal = await refusalOf(service.assertOwnsResource(owner, OTHER_ID, CONTEXT));

    expect(refusal.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden' });
  });

  it('answers a missing resource like a foreign one', async () => {
    const { service } = createService();
    const missing = await refusalOf(service.assertOwnsResource(owner, null, CONTEXT));
    const foreign = await refusalOf(service.assertOwnsResource(owner, OTHER_ID, CONTEXT));

    expect(missing.getResponse()).toEqual(foreign.getResponse());
    expect(missing.getStatus()).toBe(foreign.getStatus());
  });

  it('audits a refusal without the resource', async () => {
    const { service, audit } = createService();

    await refusalOf(service.assertOwnsResource(owner, OTHER_ID, CONTEXT));

    const record = onlyRecord(audit);

    expect(record.action).toBe('authz.denied');
    expect(record.actorId).toBe(OWNER_ID);
    expect(record.metadata).toEqual({
      actorRole: Role.USER,
      action: 'resource.ownership',
      outcome: 'denied',
    });
    expect(JSON.stringify(record)).not.toContain(OTHER_ID);
  });

  it('gives staff no bypass', async () => {
    const { service, audit } = createService();
    const admin: PolicySubject = { id: ADMIN_ID, role: Role.ADMIN };
    const staffOwner: PolicySubject = { id: ADMIN_ID, role: Role.OWNER };

    const asAdmin = await refusalOf(service.assertOwnsResource(admin, OWNER_ID, CONTEXT));
    const asOwner = await refusalOf(service.assertOwnsResource(staffOwner, OWNER_ID, CONTEXT));

    expect(asAdmin.getResponse()).toEqual(asOwner.getResponse());
    expect(audit.records).toHaveLength(2);
  });

  it('still refuses when the audit fails', async () => {
    const { service, audit, logger } = createService(new FailingAudit());

    const refusal = await refusalOf(service.assertOwnsResource(owner, OTHER_ID, CONTEXT));

    expect(refusal.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(audit.records).toHaveLength(1);

    const failure = logger.warns.find((call) => call.message === 'authz audit failed');

    expect(failure).toBeDefined();
    expect(JSON.stringify(logger.warns)).not.toContain(OWNER_ID);
    expect(JSON.stringify(logger.warns)).not.toContain(OTHER_ID);
    expect(JSON.stringify(logger.warns)).not.toContain('audit chain is unavailable');
  });
});
