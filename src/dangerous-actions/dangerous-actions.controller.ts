import { Controller, ForbiddenException, HttpCode, Param, Post, Req } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import type { Prisma } from '@prisma/client';
import type { PolicySubject } from '../auth/policy/access-policy';
import { AdminUsersService } from '../admin/admin-users.service';
import { BillingCheckoutService } from '../billing/billing-checkout.service';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { Role } from '../auth/roles';
import { DangerousActionsService } from './dangerous-actions.service';
import { PrismaService } from '../database/prisma.service';

@Controller('admin/pending-approvals')
export class DangerousActionsController {
  constructor(
    private readonly dangerous: DangerousActionsService,
    private readonly prisma: PrismaService,
    private readonly moduleRef: ModuleRef,
  ) {}

  @Post()
  @HttpCode(200)
  @Roles(Role.ADMIN, Role.OWNER)
  async list(@Req() request: AuthenticatedRequest) {
    const actor = request.auth;
    if (actor === undefined) throw new ForbiddenException();
    if (!(await this.dangerous.isApprover(actor.userId))) throw new ForbiddenException();
    return this.dangerous.list();
  }

  @Post(':id/approve')
  @HttpCode(200)
  @Roles(Role.ADMIN, Role.OWNER)
  async approve(@Param('id') id: string, @Req() request: AuthenticatedRequest) {
    const actor = request.auth;
    if (actor === undefined) throw new ForbiddenException();
    const approver: PolicySubject = { id: actor.userId, role: actor.role };
    const users = this.moduleRef.get(AdminUsersService, { strict: false });
    const billing = this.moduleRef.get(BillingCheckoutService, { strict: false });
    const requestId = String(request.id ?? id);

    const executeMap: Record<string, (payload: Prisma.JsonValue) => Promise<unknown>> = {
      ADMIN_GRANT: (payload) =>
        users.executeGrantAdmin(approver, this.requireString(payload, 'targetId'), requestId),
      ADMIN_REVOKE: (payload) =>
        users.executeRevokeAdmin(approver, this.requireString(payload, 'targetId'), requestId),
      BILLING_CHANGE_PRICE: (payload) =>
        billing.executePriceChange(approver, this.requireString(payload, 'priceUsd'), requestId),
    };

    return {
      status: 'EXECUTED',
      result: await this.dangerous.approve(actor.userId, id, executeMap),
    };
  }

  private requireString(payload: Prisma.JsonValue, field: string): string {
    if (
      typeof payload !== 'object' ||
      payload === null ||
      Array.isArray(payload) ||
      typeof payload[field] !== 'string'
    )
      throw new ForbiddenException();

    return payload[field];
  }
}
