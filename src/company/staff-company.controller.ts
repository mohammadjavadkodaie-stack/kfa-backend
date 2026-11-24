import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import { getRequestId } from '../common/middleware/request-id.middleware';
import {
  CompanyListQueryDto,
  CompanyParamsDto,
  parseCreateCompany,
  parseUpdateCompany,
} from './company.dto';
import type { CompanyRow } from './company.repository';
import { CompanyService, type CompanyPage } from './company.service';

/**
 * Staff maintenance of company profiles:
 * `GET /staff/companies`, `GET /staff/companies/:id`,
 * `POST /staff/companies`, `PATCH /staff/companies/:id` and
 * `DELETE /staff/companies/:id`.
 *
 * The guard stack is the staff write stack:
 *
 * - the global `AuthGuard` resolves the caller;
 * - the global `StaffGateGuard` keeps a staff session that never proved a second
 *   factor out of the whole controller;
 * - `@Roles(ADMIN, OWNER)` keeps every USER and ATHLETE out of every route, so
 *   the legal identity columns have no owner-facing reader at all;
 * - `@RequireStepUp()` additionally covers all three writes.
 *
 * The two reads are staff-only for now; the public card is step 9b and will
 * select the public columns on its own route. Nothing here is cacheable: the
 * module applies `noStoreMiddleware`.
 */
@Controller('staff/companies')
export class StaffCompanyController {
  constructor(private readonly companies: CompanyService) {}

  /** One page of live companies, newest first. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get()
  async list(@Query() query: CompanyListQueryDto): Promise<CompanyPage> {
    return this.companies.list(query.limit, query.cursor);
  }

  /** One live company, staff fields included. */
  @Roles(Role.ADMIN, Role.OWNER)
  @Get(':id')
  async get(@Param() params: CompanyParamsDto): Promise<CompanyRow> {
    return this.companies.get(params.id);
  }

  /** Creates one company identity card; the slug is chosen here, once. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    // zod is the whole gate, so the global pipe skips the untyped body.
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<CompanyRow> {
    const input = parseCreateCompany(body);

    return this.companies.create(input, this.actor(request), this.context(request));
  }

  /** Corrects a profile; the slug is fixed and refused by the schema. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Patch(':id')
  async update(
    @Param() params: CompanyParamsDto,
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<CompanyRow> {
    const input = parseUpdateCompany(body);

    return this.companies.update(params.id, input, this.actor(request), this.context(request));
  }

  /** Retires a company (soft delete); a repeated delete is the same 404. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param() params: CompanyParamsDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    await this.companies.delete(params.id, this.actor(request), this.context(request));
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }

  /** Request facts an audit row may carry; the service hashes the IP. */
  private context(request: AuthenticatedRequest) {
    return { requestId: getRequestId(request), ip: request.ip ?? null };
  }
}
