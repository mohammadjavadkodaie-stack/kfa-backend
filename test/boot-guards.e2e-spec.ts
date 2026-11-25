import request from 'supertest';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/app.setup';
import { ENV } from '../src/config/config.module';
import type { Env } from '../src/config/env';
import { PrismaService } from '../src/database/prisma.service';
import { REDIS_CLIENT } from '../src/rate-limit/redis-throttler.storage';
import { applyTestEnv } from './helpers/test-env';

/**
 * Production boots only with the real CAPTCHA and email providers. Every
 * production case still sets non-fake CAPTCHA and email providers, so each
 * case fails for exactly the reason it asserts.
 */
const PROD_PROVIDER_ENV = {
  CAPTCHA_PROVIDER: 'turnstile',
  TURNSTILE_SECRET_KEY: 'test-only-turnstile-secret-key',
  TURNSTILE_EXPECTED_HOSTNAME: 'app.example',
  EMAIL_PROVIDER: 'resend',
  RESEND_API_KEY: 'test-only-resend-api-key',
  EMAIL_FROM: 'KFA <no-reply@example.com>',
  // Production refuses to boot without the nightly-backup settings.
  BACKUP_ENCRYPTION_KEY: 'a2ZhLXRlc3Qtb25seS1iYWNrdXAtZW5jLWtleS0wMDE',
  BACKUP_NOTIFY_EMAIL: 'owner@example.com',
  BACKUP_NOTIFY_EMAIL_EMERGENCY: 'owner-emergency@example.com',
  // Production also validates the break-glass migration URL (used by the
  // owner bootstrap), so every production case carries a compliant value.
  MIGRATION_DATABASE_URL:
    'postgresql://kfa_migrator:test-only@db.internal:5432/kfa?sslmode=require',
} as const;

async function compileApp(): Promise<unknown> {
  try {
    await Test.createTestingModule({ imports: [AppModule] }).compile();
    return undefined;
  } catch (error) {
    return error;
  }
}

/**
 * Stand-in for the shared Redis client: the counters are not needed, only a
 * reply shaped like the Lua script's, so no request ever opens a socket.
 */
const REDIS_TEST_STUB = {
  status: 'ready',
  incrementRateLimitWindow: async (): Promise<number[]> => [1, 60_000, 0, 0],
  get: async (): Promise<string | null> => null,
  pttl: async (): Promise<number> => -2,
  del: async (): Promise<number> => 0,
  disconnect: (): void => undefined,
  quit: async (): Promise<'OK'> => 'OK',
};

/**
 * Boots the real application graph under a production environment, with the
 * two providers that would dial something replaced: Prisma (a no-connection
 * stub) and the shared Redis client (an in-memory stand-in that answers the
 * rate-limit commands without opening a socket). Guards, filters and routing
 * stay exactly as `AppModule` wires them.
 */
async function bootProductionApp(): Promise<NestExpressApplication> {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(PrismaService)
    .useValue({ $connect: async () => undefined, $disconnect: async () => undefined })
    .overrideProvider(REDIS_CLIENT)
    .useValue(REDIS_TEST_STUB)
    .compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>({
    bodyParser: false,
    bufferLogs: true,
  });

  configureApp(app, app.get<Env>(ENV));
  await app.init();

  return app;
}

describe('Boot guards (e2e)', () => {
  afterEach(() => {
    applyTestEnv();
  });

  it('fails fast when the environment is invalid', async () => {
    applyTestEnv({ APP_ORIGINS: 'not-a-url' });

    const error = await compileApp();

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('Invalid environment configuration');
    expect((error as Error).message).toContain('APP_ORIGINS');
  });

  it('never echoes the offending environment value', async () => {
    const sentinel = 'sentinel-value-must-not-leak';
    applyTestEnv({ PORT: sentinel });

    const error = await compileApp();

    expect((error as Error).message).not.toContain(sentinel);
  });

  it('rejects wildcard CORS origins', async () => {
    applyTestEnv({ APP_ORIGINS: '*' });

    const error = await compileApp();

    expect((error as Error).message).toContain('APP_ORIGINS');
  });

  it('refuses to boot in production without a shared Redis store', async () => {
    applyTestEnv({
      ...PROD_PROVIDER_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://kfa_app:test-only@db.internal:5432/kfa?sslmode=require',
    });

    const error = await compileApp();

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('Invalid environment configuration');
    expect((error as Error).message).toContain('REDIS_URL');
    expect((error as Error).message).not.toContain('CAPTCHA_PROVIDER');
  });

  it('answers a generic 404 for the removed phone routes in production', async () => {
    applyTestEnv({
      ...PROD_PROVIDER_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://kfa_app:test-only@db.internal:5432/kfa?sslmode=require',
      REDIS_URL: 'rediss://:test-only@redis.internal:6380/0',
    });

    const app = await bootProductionApp();

    try {
      for (const path of [
        '/auth/otp/start',
        '/auth/login',
        '/auth/register',
        '/auth/phone-change/start',
      ]) {
        const response = await request(app.getHttpServer()).post(path).send({});

        expect(response.status).toBe(404);
        expect(response.body).toMatchObject({ statusCode: 404, message: 'Not Found' });
        expect(response.body).not.toHaveProperty('code');
      }
    } finally {
      await app.close();
    }
  });

  it('keeps email, session and token routes live in production', async () => {
    applyTestEnv({
      ...PROD_PROVIDER_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://kfa_app:test-only@db.internal:5432/kfa?sslmode=require',
      REDIS_URL: 'rediss://:test-only@redis.internal:6380/0',
    });

    const app = await bootProductionApp();

    try {
      const response = await request(app.getHttpServer()).post('/auth/refresh').send({});

      // Anything but the route-level 404: the route exists and answers through
      // the ordinary pipeline (400/401 here, since the payload is empty).
      expect(response.status).not.toBe(404);
    } finally {
      await app.close();
    }
  });

  it('refuses a plaintext Redis URL in production without echoing its password', async () => {
    const password = 'sentinel-redis-password-must-not-leak';

    applyTestEnv({
      ...PROD_PROVIDER_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://kfa_app:test-only@db.internal:5432/kfa?sslmode=require',
      REDIS_URL: `redis://:${password}@redis.internal:6380/0`,
    });

    const error = await compileApp();

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('REDIS_URL');
    expect((error as Error).message).toMatch(/rediss/);
    expect((error as Error).message).not.toContain(password);
  });
});
