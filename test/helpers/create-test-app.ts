import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { Logger } from 'nestjs-pino';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/app.setup';
import { ENV } from '../../src/config/config.module';
import type { Env } from '../../src/config/env';
import { TestController } from './test.controller';
import { applyTestEnv, type TestEnvOverrides } from './test-env';

/**
 * Builds the real application (same module, same hardening as `main.ts`) and
 * adds test-only routes. `bodyParser: false` mirrors production, where the body
 * limit is registered by `configureApp`.
 */
export async function createTestApp(
  overrides: TestEnvOverrides = {},
): Promise<NestExpressApplication> {
  applyTestEnv(overrides);

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
    controllers: [TestController],
  }).compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>({
    bodyParser: false,
    bufferLogs: true,
  });

  app.useLogger(app.get(Logger));
  configureApp(app, app.get<Env>(ENV));

  await app.init();

  return app;
}
