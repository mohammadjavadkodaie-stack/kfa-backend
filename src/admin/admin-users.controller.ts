import { Controller, Delete, ForbiddenException, HttpCode, Param, Post, Req } from '@nestjs/common';
import { Roles } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import type { PolicySubject } from '../auth/policy/access-policy';
import { Role } from '../auth/roles';
import { RequireStepUp } from '../auth/totp/step-up.guard';
import { getRequestId } from '../common/middleware/request-id.middleware';
import { AdminUsersService } from './admin-users.service';

/**
 * Moderation, promotion and demotion of an account.
 *
 * Every route changes who may use the API, so each one carries the staff role
 * and a fresh second factor; the global staff gate stays in front of them.
 * There is no body: the only input is the id in the path, which the service
 * validates against storage.
 */
@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly users: AdminUsersService) {}

  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/block')
  @HttpCode(204)
  async block(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
    await this.users.block(this.actor(request), id, getRequestId(request));
  }

  @Roles(Role.ADMIN, Role.OWNER)
  @RequireStepUp()
  @Post(':id/unblock')
  @HttpCode(204)
  async unblock(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
    await this.users.unblock(this.actor(request), id, getRequestId(request));
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
