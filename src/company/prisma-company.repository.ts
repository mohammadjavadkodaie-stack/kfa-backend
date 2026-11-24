import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import type { CompanyPatch, CompanyRepository, CompanyRow, NewCompany } from './company.repository';

const COMPANY_FIELDS = {
  id: true,
  slug: true,
  displayName: true,
  country: true,
  kind: true,
  description: true,
  websiteUrl: true,
  legalName: true,
  tradeRegistryNumber: true,
  mersisNumber: true,
  taxNumber: true,
  taxOffice: true,
  chamberName: true,
  chamberRegisteredAt: true,
  naceCode: true,
  address: true,
  contactEmail: true,
  createdById: true,
  updatedById: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
} as const;

type CompanyModel = Prisma.CompanyGetPayload<{ select: typeof COMPANY_FIELDS }>;

/**
 * The `companies` table.
 *
 * Every write is a conditional UPDATE with `deletedAt: null` in the predicate,
 * so a soft-deleted row is invisible to a correction and a repeated delete
 * changes nothing: `count` is the gate the service turns into the generic 404.
 */
@Injectable()
export class PrismaCompanyRepository implements CompanyRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(input: NewCompany, tx: Prisma.TransactionClient): Promise<CompanyRow> {
    const row: CompanyModel = await tx.company.create({
      data: input,
      select: COMPANY_FIELDS,
    });

    return row;
  }

  async update(
    companyId: string,
    patch: CompanyPatch,
    tx: Prisma.TransactionClient,
  ): Promise<number> {
    const result = await tx.company.updateMany({
      where: { id: companyId, deletedAt: null },
      data: patch,
    });

    return result.count;
  }

  async softDelete(
    companyId: string,
    updatedById: string,
    deletedAt: Date,
    tx: Prisma.TransactionClient,
  ): Promise<number> {
    const result = await tx.company.updateMany({
      where: { id: companyId, deletedAt: null },
      data: { deletedAt, updatedById },
    });

    return result.count;
  }

  async findActiveById(
    companyId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<CompanyRow | null> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    const row: CompanyModel | null = await client.company.findFirst({
      where: { id: companyId, deletedAt: null },
      select: COMPANY_FIELDS,
    });

    return row;
  }

  async listActive(limit: number, cursor: string | undefined): Promise<CompanyRow[]> {
    // A total order (arrival, then the unique id) makes the answer stable between
    // two reads; the cursor page resumes at exactly the row it was handed.
    const rows: CompanyModel[] = await this.prisma.company.findMany({
      where: { deletedAt: null },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      ...(cursor === undefined ? {} : { cursor: { id: cursor }, skip: 1 }),
      select: COMPANY_FIELDS,
    });

    return rows;
  }
}
