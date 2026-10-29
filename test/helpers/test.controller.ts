import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Inject,
  NotFoundException,
  Post,
  Req,
} from '@nestjs/common';
import { IsOptional, IsString, MaxLength } from 'class-validator';
import { RequireVerifier, Roles } from '../../src/auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../../src/auth/guards/auth.guard';
import { InMemorySessionRepository } from '../../src/auth/in-memory-session.repository';
import { AccessPolicyService } from '../../src/auth/policy/access-policy.service';
import { Role } from '../../src/auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../../src/auth/session.repository';
import { Public } from '../../src/common/decorators/public.decorator';
import { getRequestId } from '../../src/common/middleware/request-id.middleware';

export class EchoDto {
  @IsString()
  @MaxLength(32)
  name!: string;
}

/** Body of the policy route: who to act on, what to do, and the new role if any. */
export class AuthorizeDto {
  @IsString()
  @MaxLength(64)
  targetId!: string;

  @IsString()
  @MaxLength(64)
  action!: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  role?: string;
}

/**
 * Test-only routes. They live in the test tree on purpose: the real app exposes
 * only `GET /health` so far. The role-protected routes exist so the guards can
 * be exercised over HTTP without shipping an admin endpoint.
 */
@Controller('test')
export class TestController {
  constructor(
    private readonly policy: AccessPolicyService,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
  ) {}

  @Public()
  @Get('echo')
  echo(): { ok: true } {
    return { ok: true };
  }

  @Get('protected')
  protectedRoute(): { ok: true } {
    return { ok: true };
  }

  @Roles(Role.ADMIN)
  @Get('admin')
  adminOnly(): { ok: true } {
    return { ok: true };
  }

  @Roles(Role.OWNER)
  @Get('owner')
  ownerOnly(): { ok: true } {
    return { ok: true };
  }

  @Roles(Role.ADMIN, Role.OWNER)
  @Get('staff')
  adminOrOwner(): { ok: true } {
    return { ok: true };
  }

  @RequireVerifier()
  @Get('verifier')
  verifierOnly(): { ok: true } {
    return { ok: true };
  }

  @Public()
  @Post('echo')
  create(@Body() dto: EchoDto): EchoDto {
    return dto;
  }

  /**
   * Exercises the access policy over HTTP. It is deliberately *not* marked with
   * `@Roles`: the policy, not the guard, has to answer here, and a demoted actor
   * must be refused on the next request without touching the access token.
   *
   * The target is read from the in-memory store the way an endpoint would read
   * it from the database; 204 means the policy allowed the action.
   */
  @Post('authorize')
  @HttpCode(204)
  async authorize(@Body() dto: AuthorizeDto, @Req() request: AuthenticatedRequest): Promise<void> {
    const principal = request.auth;

    // The global AuthGuard runs first, so this is a wiring bug, not input.
    if (principal === undefined) throw new ForbiddenException();

    const target = this.userStore().users.get(dto.targetId);

    if (target === undefined) throw new NotFoundException();

    await this.policy.authorize(
      { id: principal.userId, role: principal.role },
      { action: dto.action, role: dto.role ?? null },
      { id: target.id, role: target.role },
      { requestId: getRequestId(request), ip: request.ip ?? null },
    );
  }

  private userStore(): InMemorySessionRepository {
    if (!(this.sessions instanceof InMemorySessionRepository)) {
      throw new Error('the authorize route needs the in-memory session repository');
    }

    return this.sessions;
  }
}
