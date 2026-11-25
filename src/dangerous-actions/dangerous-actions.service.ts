import { ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma, PendingApproval } from '@prisma/client';
import { Role } from '../auth/roles';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { PrismaService } from '../database/prisma.service';
import { PendingApprovalRepository } from './pending-approval.repository';

export interface DangerousActor {
  readonly id: string;
  readonly role: Role;
}
export type DangerousResult<T> =
  { status: 'EXECUTED'; result: T } | { status: 'PENDING'; pendingApprovalId: string };

@Injectable()
export class DangerousActionsService {
  constructor(
    private readonly repository: PendingApprovalRepository,
    private readonly prisma: PrismaService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  async runOrQueue<T>(
    actor: DangerousActor,
    actionType: string,
    payload: Prisma.InputJsonValue,
    execute: () => Promise<T>,
  ): Promise<DangerousResult<T>> {
    if (!this.env.DANGEROUS_ACTION_APPROVAL_ENABLED || actor.role === Role.OWNER) {
      return { status: 'EXECUTED', result: await execute() };
    }
    const pending = await this.repository.create({
      actionType,
      payload,
      requestedBy: actor.id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
    return { status: 'PENDING', pendingApprovalId: pending.id };
  }

  async list(): Promise<PendingApproval[]> {
    return this.repository.list();
  }

  /**
   * Whether the user may act as an approver: an OWNER, or an ADMIN whose
   * `isApprover` flag is set. Shared by `approve` and the list endpoint.
   */
  async isApprover(userId: string): Promise<boolean> {
    const approver = await this.loadApprover(userId);
    return approver !== null && (approver.role === 'OWNER' || approver.isApprover);
  }

  private loadApprover(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: { role: true, isApprover: true },
    });
  }

  async approve(
    approverId: string,
    pendingApprovalId: string,
    executeMap: Record<string, (payload: Prisma.JsonValue) => Promise<unknown>>,
  ): Promise<unknown> {
    const approver = await this.loadApprover(approverId);
    if (approver === null || (approver.role !== 'OWNER' && !approver.isApprover))
      throw new ForbiddenException();
    const pending = await this.repository.findById(pendingApprovalId);
    if (pending === null) throw new NotFoundException();
    if (pending.status !== 'PENDING') throw new ForbiddenException();
    if (pending.expiresAt <= new Date()) {
      await this.repository.markRejectedIfExpired(pending.id);
      throw new ForbiddenException();
    }
    const execute = executeMap[pending.actionType];
    if (execute === undefined) throw new ForbiddenException();
    return this.prisma.$transaction(async (tx) => {
      const result = await execute(pending.payload);
      await this.repository.markExecuted(pending.id, approverId, new Date(), tx);
      return result;
    });
  }
}
