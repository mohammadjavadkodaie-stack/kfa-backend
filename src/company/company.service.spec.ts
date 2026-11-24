import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { AuditRecordInput, AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import type { PrismaService } from '../database/prisma.service';
import type { CompanyPatch, CompanyRepository, CompanyRow, NewCompany } from './company.repository';
import {
  COMPANY_AUDIT_ACTIONS,
  CompanyService,
  type CreateCompanyInput,
  type UpdateCompanyInput,
} from './company.service';

/**
 * The staff company service, against an in-memory table.
 *
 * The fake transaction snapshots the table and restores it on a throw, which is
 * what a real rollback does - so the audit-atomicity case proves the write is
 * undone, not merely that an exception surfaced.
 */

type MutableCompany = { -readonly [K in keyof CompanyRow]: CompanyRow[K] };

const ACTOR: PolicySubject = { id: '11111111-1111-4111-8111-111111111111', role: Role.ADMIN };
const CONTEXT: AccessPolicyContext = { requestId: 'req-company', ip: '203.0.113.9' };
const COMPANY_ID = '22222222-2222-4222-8222-222222222222';

const INPUT: CreateCompanyInput = {
  slug: 'bursa-atletizm-kulubu',
  displayName: 'Bursa Atletizm Kulübü',
  country: 'TR',
  kind: 'ORGANIZER',
  legalName: 'Bursa Atletizm Kulübü Derneği',
  taxNumber: '1234567890',
  mersisNumber: '0123456789012345',
  websiteUrl: 'https://ornek.org',
};

class FakeCompanies implements CompanyRepository {
  readonly rows: MutableCompany[] = [];

  private nextId = 0;

  async create(input: NewCompany, _tx: Prisma.TransactionClient): Promise<CompanyRow> {
    const now = new Date('2026-11-01T00:00:00.000Z');
    const id = this.nextId === 0 ? COMPANY_ID : `${COMPANY_ID}-${this.nextId}`;

    this.nextId += 1;

    const row: MutableCompany = {
      id,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
      description: null,
      websiteUrl: null,
      tradeRegistryNumber: null,
      mersisNumber: null,
      taxNumber: null,
      taxOffice: null,
      chamberName: null,
      chamberRegisteredAt: null,
      naceCode: null,
      address: null,
      contactEmail: null,
      ...input,
    };

    this.rows.push(row);

    return row;
  }

  async update(
    companyId: string,
    patch: CompanyPatch,
    _tx: Prisma.TransactionClient,
  ): Promise<number> {
    const row = this.live(companyId);

    if (row === undefined) return 0;

    Object.assign(row, patch);

    return 1;
  }

  async softDelete(
    companyId: string,
    updatedById: string,
    deletedAt: Date,
    _tx: Prisma.TransactionClient,
  ): Promise<number> {
    const row = this.live(companyId);

    if (row === undefined) return 0;

    row.deletedAt = deletedAt;
    row.updatedById = updatedById;

    return 1;
  }

  async findActiveById(companyId: string): Promise<CompanyRow | null> {
    return this.live(companyId) ?? null;
  }

  async listActive(limit: number, cursor: string | undefined): Promise<CompanyRow[]> {
    const live = this.rows
      .filter((row) => row.deletedAt === null)
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
    const start = cursor === undefined ? 0 : live.findIndex((row) => row.id === cursor) + 1;

    return live.slice(start, start + limit);
  }

  snapshot(): MutableCompany[] {
    return structuredClone(this.rows);
  }

  restore(snapshot: MutableCompany[]): void {
    this.rows.splice(0, this.rows.length, ...snapshot);
  }

  private live(companyId: string): MutableCompany | undefined {
    return this.rows.find((row) => row.id === companyId && row.deletedAt === null);
  }
}

class FakeAudit {
  readonly records: { action: string; targetId: string | null; metadata: unknown }[] = [];

  fail = false;

  async record(input: AuditRecordInput): Promise<never> {
    if (this.fail) throw new Error('audit chain unavailable');

    this.records.push({
      action: input.action,
      targetId: input.targetId ?? null,
      metadata: input.metadata,
    });

    return undefined as never;
  }
}

function createService() {
  const repository = new FakeCompanies();
  const audit = new FakeAudit();
  const prisma = {
    $transaction: async <T>(run: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> => {
      const snapshot = repository.snapshot();

      try {
        return await run({} as Prisma.TransactionClient);
      } catch (error) {
        repository.restore(snapshot);

        throw error;
      }
    },
  };
  const logger = { setContext: jest.fn(), warn: jest.fn() };
  const service = new CompanyService(
    repository,
    audit as unknown as AuditService,
    prisma as unknown as PrismaService,
    logger as never,
  );

  return { service, repository, audit, logger };
}

describe('CompanyService', () => {
  it('creates a company and writes one audit row in the same transaction', async () => {
    const { service, repository, audit } = createService();

    const created = await service.create(INPUT, ACTOR, CONTEXT);

    expect(created.slug).toBe(INPUT.slug);
    expect(created.createdById).toBe(ACTOR.id);
    expect(created.updatedById).toBe(ACTOR.id);
    expect(repository.rows).toHaveLength(1);
    expect(audit.records).toEqual([
      {
        action: COMPANY_AUDIT_ACTIONS.CREATED,
        targetId: COMPANY_ID,
        metadata: { companyId: COMPANY_ID },
      },
    ]);
  });

  it('maps a duplicate slug to the generic conflict', async () => {
    const { service, repository, logger } = createService();

    repository.create = async () => {
      throw new Prisma.PrismaClientKnownRequestError('unique constraint', {
        code: 'P2002',
        clientVersion: 'test',
      });
    };

    await expect(service.create(INPUT, ACTOR, CONTEXT)).rejects.toThrow(ConflictException);
    expect(logger.warn).toHaveBeenCalled();
  });

  it('rolls the profile back when its audit row cannot be written', async () => {
    const { service, repository, audit } = createService();

    audit.fail = true;

    await expect(service.create(INPUT, ACTOR, CONTEXT)).rejects.toThrow(
      ServiceUnavailableException,
    );
    expect(repository.rows).toEqual([]);
    expect(audit.records).toEqual([]);
  });

  it('records the changed field names and never their values', async () => {
    const { service, audit } = createService();
    const patch: UpdateCompanyInput = {
      displayName: 'Gizli Sponsor A.Ş.',
      taxNumber: '9876543210',
    };

    await service.create(INPUT, ACTOR, CONTEXT);

    const updated = await service.update(COMPANY_ID, patch, ACTOR, CONTEXT);

    expect(updated.displayName).toBe('Gizli Sponsor A.Ş.');

    const recorded = JSON.stringify(audit.records[1]?.metadata);

    expect(recorded).toContain('displayName');
    expect(recorded).toContain('taxNumber');
    expect(recorded).not.toContain('Gizli Sponsor');
    expect(recorded).not.toContain('9876543210');
    expect(audit.records[1]?.action).toBe(COMPANY_AUDIT_ACTIONS.UPDATED);
  });

  it('answers 404 for an update of a company that does not exist', async () => {
    const { service, audit } = createService();

    await expect(
      service.update('missing', { taxOffice: 'Nilüfer' }, ACTOR, CONTEXT),
    ).rejects.toThrow(NotFoundException);
    expect(audit.records).toEqual([]);
  });

  it('soft-deletes once, hides the row from the list and answers 404 the second time', async () => {
    const { service, repository, audit } = createService();

    await service.create(INPUT, ACTOR, CONTEXT);
    await service.delete(COMPANY_ID, ACTOR, CONTEXT);

    expect(repository.rows).toHaveLength(1);
    expect(repository.rows.at(0)?.deletedAt).not.toBeNull();
    await expect(service.list()).resolves.toEqual({ items: [], nextCursor: null });
    await expect(service.get(COMPANY_ID)).rejects.toThrow(NotFoundException);

    await expect(service.delete(COMPANY_ID, ACTOR, CONTEXT)).rejects.toThrow(NotFoundException);
    expect(audit.records.map((row) => row.action)).toEqual([
      COMPANY_AUDIT_ACTIONS.CREATED,
      COMPANY_AUDIT_ACTIONS.DELETED,
    ]);
  });

  it('pages newest first with the cursor at the last row of the page', async () => {
    const { service, repository } = createService();

    for (let index = 0; index < 3; index += 1) {
      await service.create({ ...INPUT, slug: `company-${index}` }, ACTOR, CONTEXT);

      const row = repository.rows.at(index);

      if (row === undefined) throw new Error('row was not stored');

      row.createdAt = new Date(Date.UTC(2026, 10, index + 1));
    }

    const first = await service.list(2);

    expect(first.items.map((row) => row.slug)).toEqual(['company-2', 'company-1']);
    expect(first.nextCursor).toBe(first.items.at(-1)?.id);

    const second = await service.list(2, first.nextCursor ?? undefined);

    expect(second.items.map((row) => row.slug)).toEqual(['company-0']);
    expect(second.nextCursor).toBeNull();
  });
});
