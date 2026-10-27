import { BadRequestException } from '@nestjs/common';
import type { AuditLog } from '@prisma/client';
import { createHmac } from 'node:crypto';
import type { Env } from '../config/env';
import type { PrismaService } from '../database/prisma.service';
import { computeAuditHash, isAuditHash, type AuditHashPayload } from './audit-canonical';
import { REDACTED_VALUE } from './audit-redaction';
import {
  AUDIT_CHAIN_LOCK_ID,
  AUDIT_CHAIN_LOCK_NAMESPACE,
  AuditService,
  type AuditRecordInput,
} from './audit.service';

const HMAC_KEY = 'unit-test-audit-hmac-key-0123456789';
const ACTOR_ID = '8c7a2f9e-4c43-4a63-9d3a-2f0f0a3b1c4d';
const HEADS_HASH = 'b'.repeat(64);

type RowData = Record<string, unknown>;

function createHarness(lastRow: { hash: string; createdAt: Date } | null = null) {
  const tx = {
    $queryRaw: jest.fn().mockResolvedValue([{ pg_advisory_xact_lock: null }]),
    auditLog: {
      findFirst: jest.fn().mockResolvedValue(lastRow),
      create: jest.fn(async ({ data }: { data: RowData }) => data),
    },
  };

  const prisma = {
    $transaction: jest.fn(async (callback: (client: typeof tx) => Promise<unknown>) =>
      callback(tx),
    ),
  };

  const service = new AuditService(
    prisma as unknown as PrismaService,
    {
      AUDIT_HMAC_KEY: HMAC_KEY,
    } as Env,
  );

  return { service, prisma, tx };
}

function createdData(tx: ReturnType<typeof createHarness>['tx']): RowData {
  const call = tx.auditLog.create.mock.calls[0] as [{ data: RowData }];

  return call[0].data;
}

describe('AuditService.record', () => {
  it('appends the first row with a null prevHash and a valid hash', async () => {
    const { service, tx } = createHarness();

    await service.record({ action: 'user.login' });

    const data = createdData(tx);

    expect(data.prevHash).toBeNull();
    expect(isAuditHash(data.hash as string)).toBe(true);
    expect(data.hash).toBe(computeAuditHash(null, data as unknown as AuditHashPayload));
    expect(data.metadata).toEqual({});
    expect(data.actorId).toBeNull();
    expect(data.actorRole).toBeNull();
  });

  it('chains from the current head and keeps timestamps strictly increasing', async () => {
    const head = new Date(Date.now() + 60_000);
    const { service, tx } = createHarness({ hash: HEADS_HASH, createdAt: head });

    await service.record({ action: 'user.login', actorId: ACTOR_ID, actorRole: 'ADMIN' });

    const data = createdData(tx);

    expect(data.prevHash).toBe(HEADS_HASH);
    expect((data.createdAt as Date).getTime()).toBe(head.getTime() + 1);
    expect(data.hash).toBe(computeAuditHash(HEADS_HASH, data as unknown as AuditHashPayload));

    const expectedPayload: AuditHashPayload = {
      id: data.id as string,
      createdAt: data.createdAt as Date,
      actorId: ACTOR_ID,
      actorRole: 'ADMIN',
      action: 'user.login',
      targetType: null,
      targetId: null,
      requestId: null,
      ipHash: null,
      metadata: {},
    };

    expect(data.hash).toBe(computeAuditHash(HEADS_HASH, expectedPayload));
  });

  it('takes the chain advisory lock before reading the head', async () => {
    const { service, tx } = createHarness();

    await service.record({ action: 'user.login' });

    const [strings, ...args] = tx.$queryRaw.mock.calls[0] as [TemplateStringsArray, ...unknown[]];

    expect(strings.join('?')).toContain('pg_advisory_xact_lock');
    expect(args).toEqual([AUDIT_CHAIN_LOCK_NAMESPACE, AUDIT_CHAIN_LOCK_ID]);

    const lockOrder = tx.$queryRaw.mock.invocationCallOrder[0] ?? Number.MAX_SAFE_INTEGER;
    const readOrder = tx.auditLog.findFirst.mock.invocationCallOrder[0] ?? -1;

    expect(lockOrder).toBeLessThan(readOrder);
  });

  it('redacts sensitive metadata before it reaches the database', async () => {
    const { service, tx } = createHarness();

    await service.record({
      action: 'user.login',
      metadata: { email: 'user@example.com', password: 'p@ssw0rd', nested: { otp: '123456' } },
    });

    expect(createdData(tx).metadata).toEqual({
      email: 'user@example.com',
      password: REDACTED_VALUE,
      nested: { otp: REDACTED_VALUE },
    });
  });

  it('hashes the client IP and never stores the raw value', async () => {
    const { service, tx } = createHarness();
    const ip = '203.0.113.7';

    await service.record({ action: 'user.login', ip });

    const data = createdData(tx);

    expect(data.ipHash).toBe(createHmac('sha256', HMAC_KEY).update(ip).digest('hex'));
    expect(JSON.stringify(data)).not.toContain(ip);
  });

  it('ignores caller-supplied hash, prevHash, id and createdAt', async () => {
    const { service, tx } = createHarness();
    const forged = {
      action: 'user.login',
      hash: 'f'.repeat(64),
      prevHash: 'e'.repeat(64),
      id: '00000000-0000-4000-8000-000000000000',
      createdAt: new Date(0),
    } as unknown as AuditRecordInput;

    await service.record(forged);

    const data = createdData(tx);

    expect(data.hash).not.toBe('f'.repeat(64));
    expect(data.prevHash).toBeNull();
    expect(data.id).not.toBe('00000000-0000-4000-8000-000000000000');
    expect((data.createdAt as Date).getTime()).toBeGreaterThan(0);
  });

  it('fails closed when the stored head hash is malformed', async () => {
    const { service, tx } = createHarness({ hash: 'corrupted', createdAt: new Date() });

    await expect(service.record({ action: 'user.login' })).rejects.toThrow(/chain is corrupt/);
    expect(tx.auditLog.create).not.toHaveBeenCalled();
  });

  it.each([
    ['a missing action', { action: '' }],
    ['an oversized action', { action: 'a'.repeat(201) }],
    ['an action with whitespace', { action: 'user login' }],
    ['a non-uuid actorId', { action: 'user.login', actorId: 'not-a-uuid' }],
    ['a non-string ip', { action: 'user.login', ip: 123 }],
    ['an oversized targetId', { action: 'user.login', targetId: 'x'.repeat(201) }],
  ])('rejects %s without echoing the value', async (_label, input) => {
    const { service, tx } = createHarness();

    await expect(service.record(input as AuditRecordInput)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(tx.auditLog.create).not.toHaveBeenCalled();
  });

  it('exposes no mutation API at all', () => {
    const proto = AuditService.prototype as unknown as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(AuditService.prototype).filter(
      (name) => name !== 'constructor',
    );

    expect(methods).toEqual(['record']);
    expect(proto.update).toBeUndefined();
    expect(proto.delete).toBeUndefined();
    expect(proto.deleteMany).toBeUndefined();
  });
});

describe('AuditService.record (database call shape)', () => {
  it('runs inside a single interactive transaction', async () => {
    const { service, prisma } = createHarness();

    await service.record({ action: 'user.login' });

    const calls = prisma.$transaction.mock.calls as unknown as Array<[unknown, unknown]>;

    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(calls[0]).toHaveLength(2);
    expect(calls[0]?.[1]).toEqual({ maxWait: 5_000, timeout: 10_000 });
  });
});

describe('AuditLog', () => {
  it('is returned as the persisted row', async () => {
    const { service } = createHarness();
    const row = (await service.record({ action: 'user.login' })) as unknown as AuditLog;

    expect(row.action).toBe('user.login');
  });
});
