import { Body, Controller, Get, Post } from '@nestjs/common';
import { IsString, MaxLength } from 'class-validator';
import { RequireVerifier, Roles } from '../../src/auth/decorators/roles.decorator';
import { Role } from '../../src/auth/roles';
import { Public } from '../../src/common/decorators/public.decorator';

export class EchoDto {
  @IsString()
  @MaxLength(32)
  name!: string;
}

/**
 * Test-only routes. They live in the test tree on purpose: the real app exposes
 * only `GET /health` so far. The role-protected routes exist so the guards can
 * be exercised over HTTP without shipping an admin endpoint.
 */
@Controller('test')
export class TestController {
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
}
