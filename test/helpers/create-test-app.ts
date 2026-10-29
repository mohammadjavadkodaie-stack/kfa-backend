import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test, type TestingModuleBuilder } from '@nestjs/testing';
import { Logger } from 'nestjs-pino';
import { AppModule } from '../../src/app.module';
import { configureApp } from '../../src/app.setup';
import { AuthModule } from '../../src/auth/auth.module';
import { PROOF_NONCE_STORE, type ProofNonceStore } from '../../src/auth/otp/proof-token';
import { SESSION_REPOSITORY, type SessionRepository } from '../../src/auth/session.repository';
import { ENV } from '../../src/config/config.module';
import type { Env } from '../../src/config/env';
import { PrismaService } from '../../src/database/prisma.service';
import { RateLimitService } from '../../src/rate-limit/rate-limit.service';
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

/**
 * Optional replacements for the default no-connection Prisma stub and for the
 * providers that need a database, Redis or a real secret.
 */
export interface CreateTestAppOptions {
  readonly prisma?: object;
  /** In-memory session store, so auth flows run without PostgreSQL. */
  readonly sessionRepository?: SessionRepository;
  /** Lets `ProofTokenService` keep nonces without Redis. */
  readonly proofNonceStore?: ProofNonceStore;
  /** Allows the explicit auth limits without a Redis store. */
  readonly rateLimit?: RateLimitService;
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

  let builder: TestingModuleBuilder = Test.createTestingModule({
    // `AuthModule` is imported as well so the test controller can inject the
    // auth providers (`AccessPolicyService`, the session repository) that the
    // application module keeps to itself. Nest shares one instance per module.
    imports: [AppModule, AuthModule],
    controllers: [TestController],
  })
    .overrideProvider(PrismaService)
    .useValue(options.prisma ?? PRISMA_TEST_STUB);

  if (options.sessionRepository !== undefined) {
    builder = builder.overrideProvider(SESSION_REPOSITORY).useValue(options.sessionRepository);
  }

  if (options.proofNonceStore !== undefined) {
    builder = builder.overrideProvider(PROOF_NONCE_STORE).useValue(options.proofNonceStore);
  }

  if (options.rateLimit !== undefined) {
    builder = builder.overrideProvider(RateLimitService).useValue(options.rateLimit);
  }

  const moduleRef = await builder.compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>({
    bodyParser: false,
    bufferLogs: true,
  });

  app.useLogger(app.get(Logger));
  configureApp(app, app.get<Env>(ENV));

  await app.init();

  return app;
}
