import { Injectable } from '@nestjs/common';
import type { Prisma, PendingApproval } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';

export interface PendingApprovalCreate {
  actionType: string;
  payload: Prisma.InputJsonValue;
  requestedBy: string;
  expiresAt: Date;
}

@Injectable()
export class PendingApprovalRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(
    input: PendingApprovalCreate,
    client: Prisma.TransactionClient | PrismaService = this.prisma,
  ): Promise<PendingApproval> {
    return client.pendingApproval.create({ data: input });
  }

  findById(
    id: string,
    client: Prisma.TransactionClient | PrismaService = this.prisma,
  ): Promise<PendingApproval | null> {
    return client.pendingApproval.findUnique({ where: { id } });
  }

  markExecuted(
    id: string,
    approvedBy: string,
    approvedAt: Date,
    client: Prisma.TransactionClient | PrismaService = this.prisma,
  ): Promise<PendingApproval> {
    return client.pendingApproval.update({
      where: { id },
      data: { status: 'EXECUTED', executedAt: approvedAt, approvedBy, approvedAt },
    });
  }

  async markRejectedIfExpired(
    id: string,
    now = new Date(),
    client: Prisma.TransactionClient | PrismaService = this.prisma,
  ): Promise<boolean> {
    const result = await client.pendingApproval.updateMany({
      where: { id, status: 'PENDING', expiresAt: { lte: now } },
      data: { status: 'REJECTED' },
    });
    return result.count === 1;
  }

  list(client: Prisma.TransactionClient | PrismaService = this.prisma): Promise<PendingApproval[]> {
    return client.pendingApproval.findMany({
      where: { status: 'PENDING' },
      orderBy: { createdAt: 'asc' },
    });
  }
}
