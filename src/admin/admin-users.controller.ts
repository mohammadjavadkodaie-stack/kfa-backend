import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  Param,
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
import { AdminUsersQueryDto, parseModerationReason, toAdminUsersFilter } from './admin-users.dto';
import { AdminUsersService, type AdminUsersPageView } from './admin-users.service';

/**
 * Moderation, promotion and demotion of an account, plus the account list.
 *
 * Every route carries the staff role and a fresh second factor; the global
 * staff gate stays in front of them. The two moderation routes also carry a
 * required `reason` in the body, which the zod schema parses before the service
 * runs and which lands in the audit row and nowhere else. The remaining
 * mutations take no body: their only input is the id in the path, which the
 * service validates against storage. The one read takes the same gates, because
 * a page of accounts is every address at once.
 */
@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly users: AdminUsersService) {}

  /**
   * One page of accounts, oldest first. Read-only, so it records what was
   * listed instead of what changed - and still refuses to serve when that
   * record cannot be written. The step-up stays: the page hands out every
   * address at once, so a stolen staff session must not be enough to list it.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Get()
  async list(
    @Query() query: AdminUsersQueryDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<AdminUsersPageView> {
    return this.users.list(this.actor(request), toAdminUsersFilter(query), getRequestId(request));
  }

  /**
   * Blocks an account. The reason is validated at the wire gate, reaches the
   * service as a plain string and is written to the audit row only.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/block')
  @HttpCode(204)
  async block(
    @Param('id') id: string,
    // zod is the whole gate, so the global pipe skips the untyped body.
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    const { reason } = parseModerationReason(body);

    await this.users.block(this.actor(request), id, getRequestId(request), reason);
  }

  /** Unblocks an account; the same required reason, the same wire gate. */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/unblock')
  @HttpCode(204)
  async unblock(
    @Param('id') id: string,
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    const { reason } = parseModerationReason(body);

    await this.users.unblock(this.actor(request), id, getRequestId(request), reason);
  }

  /**
   * Promotion to admin. The markers admit both staff roles so the policy decides:
   * only the owner may promote, and an admin actor is refused there with the
   * same generic 403 as every other refusal.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/admin')
  @HttpCode(204)
  async grantAdmin(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
    await this.users.grantAdmin(this.actor(request), id, getRequestId(request));
  }

  /**
   * Demotion. The same markers, for the same reason: only the owner may demote,
   * and an admin actor is refused by the policy with the generic 403.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Delete(':id/admin')
  @HttpCode(204)
  async revokeAdmin(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
    await this.users.revokeAdmin(this.actor(request), id, getRequestId(request));
  }

  /**
   * Owner-initiated second-factor reset: the one path back for an admin who
   * lost the device and the recovery codes. No body; the target keeps its role.
   */
  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/totp/reset')
  @HttpCode(204)
  async resetTotp(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
    await this.users.resetTotp(this.actor(request), id, getRequestId(request));
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): PolicySubject {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId, role: principal.role };
  }
}
