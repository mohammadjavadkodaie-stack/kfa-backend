import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Public } from '../common/decorators/public.decorator';

export interface HealthResponse {
  readonly status: 'ok';
}

/**
 * Minimal liveness endpoint. Deliberately exposes no version, environment,
 * build or dependency information.
 *
 * Throttling is skipped on purpose: liveness must never depend on the shared
 * Redis store, otherwise a Redis outage would look like a dead process.
 */
@SkipThrottle()
@Controller('health')
export class HealthController {
  @Public()
  @Get()
  check(): HealthResponse {
    return { status: 'ok' };
  }
}
