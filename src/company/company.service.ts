import {
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { Prisma, type CompanyKind } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { PrismaService } from '../database/prisma.service';
import { DEFAULT_COMPANY_PAGE_SIZE, MAX_COMPANY_PAGE_SIZE } from './company.dto';
import {
  COMPANY_REPOSITORY,
  type CompanyPatch,
  type CompanyRepository,
  type CompanyRow,
} from './company.repository';

/** The closed set of audit actions this feature writes. */
export const COMPANY_AUDIT_ACTIONS = {
  CREATED: 'company.created',
  UPDATED: 'company.updated',
  DELETED: 'company.deleted',
} as const;

/** The audit target of a company route. */
const COMPANY_TARGET_TYPE = 'company';

/** What `POST /staff/companies` carries once the wire gate has parsed it. */
export interface CreateCompanyInput {
  readonly slug: string;
  readonly displayName: string;
  readonly country: string;
  readonly kind: CompanyKind;
  readonly description?: string | null;
  readonly websiteUrl?: string | null;
  readonly legalName: string;
  readonly tradeRegistryNumber?: string | null;
  readonly mersisNumber?: string | null;
  readonly taxNumber?: string | null;
  readonly taxOffice?: string | null;
  readonly chamberName?: string | null;
  readonly chamberRegisteredAt?: Date | null;
  readonly naceCode?: string | null;
  readonly address?: string | null;
  readonly contactEmail?: string | null;
}

/** What `PATCH /staff/companies/:id` carries; `slug` is not correctable. */
export type UpdateCompanyInput = Partial<Omit<CreateCompanyInput, 'slug'>>;

/** One page of the staff list. */
export interface CompanyPage {
  readonly items: readonly CompanyRow[];
  readonly nextCursor: string | null;
}

/**
 * Staff-side company profiles: create, correct, retire, list, read.
 *
 * Each write and its audit row share one transaction. An audit row that cannot
 * be written rolls the change back rather than leave a profile nobody can
 * account for; the caller sees the generic 503 the other staff writes return.
 */
@Injectable()
export class CompanyService {
  constructor(
    @Inject(COMPANY_REPOSITORY) private readonly repository: CompanyRepository,
    private readonly audit: AuditService,
    private readonly prisma: PrismaService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(CompanyService.name);
  }

  /**
   * Creates one company and writes its audit row in the same transaction: a
   * profile without its audit trail must not be able to exist.
   */
  async create(
    input: CreateCompanyInput,
    actor: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<CompanyRow> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        const company = await this.repository.create(
          { ...input, createdById: actor.id, updatedById: actor.id },
          tx,
        );

        await this.record(COMPANY_AUDIT_ACTIONS.CREATED, actor, company.id, context, tx, {
          companyId: company.id,
        });

        return company;
      });
    } catch (error) {
      throw this.mapWriteError(error, input.slug);
    }
  }

  /**
   * Corrects the profile of a live company. The slug is fixed at creation and
   * never passes through here. The audit row records which fields changed, never
   * their values: the values already sit in the row, and the log must not become
   * a second copy of staff-only legal data.
   */
  async update(
    companyId: string,
    input: UpdateCompanyInput,
    actor: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<CompanyRow> {
    const patch: CompanyPatch = { ...input, updatedById: actor.id };
    const fields = Object.keys(input);

    try {
      const company = await this.prisma.$transaction(async (tx) => {
        const changed = await this.repository.update(companyId, patch, tx);

        // Nothing changed: missing, already deleted, or a write on a retired row.
        if (changed === 0) return null;

        await this.record(COMPANY_AUDIT_ACTIONS.UPDATED, actor, companyId, context, tx, {
          companyId,
          fields,
        });

        return this.repository.findActiveById(companyId, tx);
      });

      if (company === null) throw new NotFoundException();

      return company;
    } catch (error) {
      throw this.mapWriteError(error);
    }
  }

  /**
   * Retires a live company: one conditional UPDATE stamps `deletedAt`. A second
   * delete and a delete of a missing id change nothing and both get the same
   * generic 404, so the route reveals no history.
   */
  async delete(
    companyId: string,
    actor: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<void> {
    try {
      const deleted = await this.prisma.$transaction(async (tx) => {
        const changed = await this.repository.softDelete(companyId, actor.id, new Date(), tx);

        if (changed === 0) return false;

        await this.record(COMPANY_AUDIT_ACTIONS.DELETED, actor, companyId, context, tx, {
          companyId,
        });

        return true;
      });

      if (!deleted) throw new NotFoundException();
    } catch (error) {
      throw this.mapWriteError(error);
    }
  }

  /** Live companies, newest first, one page. */
  async list(limit?: number, cursor?: string): Promise<CompanyPage> {
    const capped = Math.min(limit ?? DEFAULT_COMPANY_PAGE_SIZE, MAX_COMPANY_PAGE_SIZE);
    const rows = await this.repository.listActive(capped + 1, cursor);

    if (rows.length <= capped) {
      return { items: rows, nextCursor: null };
    }

    // The extra row is not part of the answer; the row before it is the last one
    // the caller receives, so its id is where the next page starts.
    const items = rows.slice(0, capped);
    const last = items.at(-1);

    return { items, nextCursor: last === undefined ? null : last.id };
  }

  /** One live company by id; a soft-deleted one is not found. */
  async get(companyId: string): Promise<CompanyRow> {
    const company = await this.repository.findActiveById(companyId);

    if (company === null) throw new NotFoundException();

    return company;
  }

  /**
   * One audit row, inside the caller's transaction. A failure here must roll the
   * profile change back: the log is the only account of who changed what.
   */
  private async record(
    action: string,
    actor: PolicySubject,
    companyId: string,
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.audit.record(
        {
          action,
          actorId: actor.id,
          actorRole: String(actor.role),
          targetType: COMPANY_TARGET_TYPE,
          targetId: companyId,
          requestId: context.requestId,
          ip: context.ip,
          metadata,
        },
        tx,
      );
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'staff company audit failed');

      throw new ServiceUnavailableException();
    }
  }

  /** The only write race worth naming is the unique slug; anything else is 500. */
  private mapWriteError(error: unknown, slug?: string): unknown {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      this.logger.warn({ slug }, 'duplicate company slug');

      return new ConflictException();
    }

    return error;
  }
}
