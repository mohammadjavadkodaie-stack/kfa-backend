import { Controller, Get, Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { Test } from '@nestjs/testing';
import { Logger, LoggerModule } from 'nestjs-pino';
import request from 'supertest';
import { configureApp } from '../src/app.setup';
import { AuthGuard } from '../src/auth/guards/auth.guard';
import { Public } from '../src/common/decorators/public.decorator';
import { AllExceptionsFilter } from '../src/common/filters/all-exceptions.filter';
import { loadEnv } from '../src/config/env';
import { createTestApp } from './helpers/create-test-app';
import { applyTestEnv } from './helpers/test-env';

/** Small window so the limit is reached quickly; the guard itself is the real one. */
const TEST_LIMIT = 2;

/**
 * Points at a port nothing listens on, so the shared store is configured but
 * unreachable - exactly the situation a Redis outage produces in production.
 */
const UNREACHABLE_REDIS_URL = 'redis://:test-only-password@127.0.0.1:6390/0';

@Controller('limited')
class LimitedController {
  @Public()
  @Get()
  ping(): { status: 'ok' } {
    return { status: 'ok' };
  }
}

@Module({
  imports: [
    LoggerModule.forRoot({ pinoHttp: { level: 'silent' } }),
    ThrottlerModule.forRoot([{ name: 'default', ttl: 60_000, limit: TEST_LIMIT }]),
  ],
  controllers: [LimitedController],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
class RateLimitTestModule {}

describe('Rate limiting (e2e)', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    applyTestEnv();

    const moduleRef = await Test.createTestingModule({ imports: [RateLimitTestModule] }).compile();

    app = moduleRef.createNestApplication<NestExpressApplication>({
      bodyParser: false,
      bufferLogs: true,
    });

    app.useLogger(app.get(Logger));
    configureApp(app, loadEnv(process.env));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns 429 after the configured limit, with the generic envelope', async () => {
    await request(app.getHttpServer()).get('/limited').expect(200);
    await request(app.getHttpServer()).get('/limited').expect(200);

    const response = await request(app.getHttpServer()).get('/limited').expect(429);

    expect(response.body).toEqual({
      statusCode: 429,
      message: 'Too Many Requests',
      requestId: expect.any(String) as string,
    });
    expect(response.text).not.toContain('stack');
  });
});

/**
 * Fail-closed contract: a configured but unreachable store must reject
 * rate-limited traffic instead of silently allowing it, and must not take down
 * the liveness endpoint (no Redis dial happens at boot).
 */
describe('Rate limiting with an unreachable Redis store (e2e)', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApp({ REDIS_URL: UNREACHABLE_REDIS_URL });
  });

  afterAll(async () => {
    await app.close();
    // Do not leak the override into the next suite in the same process.
    applyTestEnv();
  });

  it('serves the non-throttled liveness endpoint', async () => {
    const response = await request(app.getHttpServer()).get('/health').expect(200);

    expect(response.body).toEqual({ status: 'ok' });
  });

  it('fails closed with a generic 503 on a rate-limited route', async () => {
    const response = await request(app.getHttpServer()).get('/test/echo').expect(503);

    expect(response.body).toEqual({
      statusCode: 503,
      message: 'Service Unavailable',
      requestId: expect.any(String) as string,
    });
    expect(response.text).not.toContain('ECONNREFUSED');
    expect(response.text).not.toContain('127.0.0.1');
    expect(response.text).not.toContain('stack');
  });

  it('keeps denying while the store stays down', async () => {
    await request(app.getHttpServer()).get('/test/echo').expect(503);
    await request(app.getHttpServer()).get('/test/echo').expect(503);
  });
});
