import { ForbiddenException } from '@nestjs/common';
import type { PendingApproval } from '@prisma/client';
import { Role } from '../auth/roles';
import { AdminUsersService } from '../admin/admin-users.service';
import { BillingCheckoutService } from '../billing/billing-checkout.service';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { DangerousActionsController } from './dangerous-actions.controller';
import { DangerousActionsService } from './dangerous-actions.service';

const APPROVER_ID = 'owner-1';
const TARGET_ID = 'target-1';
const REQUEST_ID = 'request-1';

const pending = (actionType: string, payload: Record<string, string>): PendingApproval => ({
  id: 'pending-1',
  actionType,
  payload,
  requestedBy: 'admin-1',
  status: 'PENDING',
  expiresAt: new Date(Date.now() + 60_000),
  createdAt: new Date(),
  executedAt: null,
  approvedBy: null,
  approvedAt: null,
});

function createController(row: PendingApproval) {
  const users = {
    executeGrantAdmin: jest.fn(async (_actor, targetId: string) => {
      roleRepository.set(targetId, Role.ADMIN);
    }),
    executeRevokeAdmin: jest.fn(),
  };
  const billing = {
    executePriceChange: jest.fn(async (_actor, priceUsd: string) => {
      priceRepository.priceUsd = priceUsd;
      return { code: 'standard', priceUsd };
    }),
  };
  const dangerous = {
    approve: jest.fn(async (_approverId, _pendingId, executeMap) =>
      executeMap[row.actionType](row.payload),
    ),
  };
  const moduleRef = {
    get: jest.fn((token) => (token === AdminUsersService ? users : billing)),
  };
  const controller = new DangerousActionsController(
    dangerous as unknown as DangerousActionsService,
    {} as never,
    moduleRef as never,
  );

  return { controller, users, billing, dangerous };
}

const roleRepository = new Map<string, Role>();
const priceRepository = { priceUsd: '4.20' };
const request = {
  id: REQUEST_ID,
  auth: { userId: APPROVER_ID, role: Role.OWNER },
} as unknown as AuthenticatedRequest;

function createListController(role: Role, isApprover: boolean) {
  const row = pending('ADMIN_GRANT', { targetId: TARGET_ID, role: Role.ADMIN });
  const prisma = {
    user: { findUnique: jest.fn(async () => ({ role, isApprover })) },
  };
  const repository = { list: jest.fn(async () => [row]) };
  const service = new DangerousActionsService(
    repository as never,
    prisma as never,
    { DANGEROUS_ACTION_APPROVAL_ENABLED: true } as never,
  );
  const controller = new DangerousActionsController(
    service,
    prisma as never,
    { get: jest.fn() } as never,
  );

  return { controller, repository };
}

function listRequest(role: Role) {
  return {
    id: REQUEST_ID,
    auth: { userId: 'actor-1', role },
  } as unknown as AuthenticatedRequest;
}

describe('DangerousActionsController list authorization', () => {
  it('forbids an ADMIN who is not an approver and returns no data', async () => {
    const { controller, repository } = createListController(Role.ADMIN, false);

    await expect(controller.list(listRequest(Role.ADMIN))).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect(repository.list).not.toHaveBeenCalled();
  });

  it('returns the pending list for an OWNER', async () => {
    const { controller, repository } = createListController(Role.OWNER, false);

    await expect(controller.list(listRequest(Role.OWNER))).resolves.toHaveLength(1);
    expect(repository.list).toHaveBeenCalledTimes(1);
  });

  it('returns the pending list for an ADMIN who is an approver', async () => {
    const { controller, repository } = createListController(Role.ADMIN, true);

    await expect(controller.list(listRequest(Role.ADMIN))).resolves.toHaveLength(1);
    expect(repository.list).toHaveBeenCalledTimes(1);
  });
});

describe('DangerousActionsController approval handlers', () => {
  beforeEach(() => {
    roleRepository.clear();
    priceRepository.priceUsd = '4.20';
  });

  it('executes a pending change_price against the real billing handler and forwards the stored value', async () => {
    const row = pending('BILLING_CHANGE_PRICE', { priceUsd: '9.99' });
    const { controller, billing } = createController(row);

    await controller.approve(row.id, request);

    expect(billing.executePriceChange).toHaveBeenCalledWith(
      { id: APPROVER_ID, role: Role.OWNER },
      '9.99',
      REQUEST_ID,
    );
    expect(priceRepository.priceUsd).toBe('9.99');
  });

  it('executes a pending grant_admin against the real admin handler and forwards the stored target id', async () => {
    const row = pending('ADMIN_GRANT', { targetId: TARGET_ID, role: Role.ADMIN });
    const { controller, users } = createController(row);

    await controller.approve(row.id, request);

    expect(users.executeGrantAdmin).toHaveBeenCalledWith(
      { id: APPROVER_ID, role: Role.OWNER },
      TARGET_ID,
      REQUEST_ID,
    );
    expect(roleRepository.get(TARGET_ID)).toBe(Role.ADMIN);
  });
});
