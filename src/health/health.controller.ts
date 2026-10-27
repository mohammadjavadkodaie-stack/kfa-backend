import { Controller, Get } from '@nestjs/common';
import { Public } from '../common/decorators/public.decorator';

export interface HealthResponse {
  readonly status: 'ok';
}

/**
 * Minimal liveness endpoint. Deliberately exposes no version, environment,
 * build or dependency information.
 */
@Controller('health')
export class HealthController {
  @Public()
  @Get()
  check(): HealthResponse {
    return { status: 'ok' };
  }
}
