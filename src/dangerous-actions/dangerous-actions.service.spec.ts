import { ForbiddenException } from '@nestjs/common';
import type { PendingApproval } from '@prisma/client';
import { Role } from '../auth/roles';
import { DangerousActionsService } from './dangerous-actions.service';

const base = (overrides: Partial<PendingApproval> = {}): PendingApproval => ({
  id: 'pending-1',
  actionType: 'TEST',
  payload: { value: 1 },
  requestedBy: 'user-1',
  status: 'PENDING',
  expiresAt: new Date(Date.now() + 60_000),
  createdAt: new Date(),
  executedAt: null,
  approvedBy: null,
  approvedAt: null,
  ...overrides,
});

class Repo {
  row = base();
  created = 0;
  rejected = 0;
  executed = 0;
  async create(): Promise<PendingApproval> {
    this.created += 1;
    return this.row;
  }
  async findById(): Promise<PendingApproval | null> {
    return this.row;
  }
  async markRejectedIfExpired(): Promise<boolean> {
    this.rejected += 1;
    this.row = { ...this.row, status: 'REJECTED' };
    return true;
  }
  async markExecuted(id: string, approvedBy: string, approvedAt: Date): Promise<PendingApproval> {
    this.executed += 1;
    this.row = {
      ...this.row,
      id,
      status: 'EXECUTED',
      approvedBy,
      approvedAt,
      executedAt: approvedAt,
    };
    return this.row;
  }
  async list(): Promise<PendingApproval[]> {
    return [this.row];
  }
}

class Prisma {
  user = {
    findUnique: async ({ where: { id } }: { where: { id: string } }) =>
      id === 'owner'
        ? { role: 'OWNER', isApprover: false }
        : id === 'approver'
          ? { role: 'ADMIN', isApprover: true }
          : { role: 'ADMIN', isApprover: false },
  };
  async $transaction<T>(work: (tx: unknown) => Promise<T>): Promise<T> {
    return work({});
  }
}

const buildService = (enabled = true, repo = new Repo(), prisma = new Prisma()) => ({
  service: new DangerousActionsService(
    repo as never,
    prisma as never,
    { DANGEROUS_ACTION_APPROVAL_ENABLED: enabled } as never,
  ),
  repo,
});

describe('DangerousActionsService', () => {
  it('executes directly for owner without a record', async () => {
    const { service, repo } = buildService();
    const execute = jest.fn().mockResolvedValue('ok');
    await expect(
      service.runOrQueue({ id: 'owner', role: Role.OWNER }, 'TEST', {}, execute),
    ).resolves.toEqual({ status: 'EXECUTED', result: 'ok' });
    expect(execute).toHaveBeenCalledTimes(1);
    expect(repo.created).toBe(0);
  });
  it('queues admin actions and does not execute', async () => {
    const { service, repo } = buildService();
    const execute = jest.fn();
    await expect(
      service.runOrQueue({ id: 'admin', role: Role.ADMIN }, 'TEST', {}, execute),
    ).resolves.toEqual({ status: 'PENDING', pendingApprovalId: 'pending-1' });
    expect(execute).not.toHaveBeenCalled();
    expect(repo.created).toBe(1);
  });
  it('executes directly when approval is disabled', async () => {
    const { service, repo } = buildService(false);
    const execute = jest.fn().mockResolvedValue(3);
    await expect(
      service.runOrQueue({ id: 'admin', role: Role.ADMIN }, 'TEST', {}, execute),
    ).resolves.toEqual({ status: 'EXECUTED', result: 3 });
    expect(repo.created).toBe(0);
  });
  it('propagates a create failure and never executes', async () => {
    const { service } = buildService();
    const execute = jest.fn();
    (service as any).repository.create = jest.fn().mockRejectedValue(new Error('db'));
    await expect(
      service.runOrQueue({ id: 'admin', role: Role.ADMIN }, 'TEST', {}, execute),
    ).rejects.toThrow('db');
    expect(execute).not.toHaveBeenCalled();
  });
  it('rejects a non-approver', async () => {
    const { service } = buildService();
    await expect(
      service.approve('admin', 'pending-1', { TEST: async () => undefined }),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });
  it('expires without executing', async () => {
    const repo = new Repo();
    repo.row = base({ expiresAt: new Date(Date.now() - 1) });
    const { service } = buildService(true, repo);
    const execute = jest.fn();
    await expect(
      service.approve('approver', 'pending-1', { TEST: execute }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(repo.rejected).toBe(1);
    expect(execute).not.toHaveBeenCalled();
  });
  it('executes a valid approval exactly once and marks it executed', async () => {
    const { service, repo } = buildService();
    const execute = jest.fn().mockResolvedValue('done');
    await expect(service.approve('approver', 'pending-1', { TEST: execute })).resolves.toBe('done');
    expect(execute).toHaveBeenCalledTimes(1);
    expect(repo.executed).toBe(1);
    expect(repo.row.status).toBe('EXECUTED');
  });
});
