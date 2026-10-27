import { Body, Controller, Get, Post } from '@nestjs/common';
import { IsString, MaxLength } from 'class-validator';
import { Public } from '../../src/common/decorators/public.decorator';

export class EchoDto {
  @IsString()
  @MaxLength(32)
  name!: string;
}

/**
 * Test-only routes. They live in the test tree on purpose: the real app exposes
 * only `GET /health` so far.
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

  @Public()
  @Post('echo')
  create(@Body() dto: EchoDto): EchoDto {
    return dto;
  }
}
