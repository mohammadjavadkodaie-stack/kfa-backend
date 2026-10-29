import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { Logger } from 'nestjs-pino';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/app.setup';
import { ENV } from '../../src/config/config.module';
import type { Env } from '../../src/config/env';
import { PrismaService } from '../../src/database/prisma.service';
import { TestController } from './test.controller';
import { applyTestEnv, type TestEnvOverrides } from './test-env';

/**
 * Replaces the Prisma client so the API suites never open a connection. The
 * audit service is still constructed (it only stores the reference), so the DI
 * graph stays identical to production.
 */
const PRISMA_TEST_STUB = {
  $connect: (): Promise<void> => Promise.resolve(),
  $disconnect: (): Promise<void> => Promise.resolve(),
};

/** Optional replacements for the default no-connection Prisma stub. */
export interface CreateTestAppOptions {
  readonly prisma?: object;
}

/**
 * Builds the real application (same module, same hardening as `main.ts`) and
 * adds test-only routes. `bodyParser: false` mirrors production, where the body
 * limit is registered by `configureApp`.
 *
 * `options.prisma` replaces the no-connection stub, e.g. with an in-memory
 * client, for suites that need a service (such as the audit chain) to actually
 * write rows.
 */
export async function createTestApp(
  overrides: TestEnvOverrides = {},
  options: CreateTestAppOptions = {},
): Promise<NestExpressApplication> {
  applyTestEnv(overrides);

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
    controllers: [TestController],
  })
    .overrideProvider(PrismaService)
    .useValue(options.prisma ?? PRISMA_TEST_STUB)
    .compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>({
    bodyParser: false,
    bufferLogs: true,
  });

  app.useLogger(app.get(Logger));
  configureApp(app, app.get<Env>(ENV));

  await app.init();

  return app;
}
