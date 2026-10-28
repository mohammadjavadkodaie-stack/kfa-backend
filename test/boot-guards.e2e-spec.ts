import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { applyTestEnv } from './helpers/test-env';

/**
 * Production refuses fake providers, so every production boot-guard case sets
 * non-fake ones. That keeps each case failing for exactly the reason it asserts.
 */
const PROD_PROVIDER_ENV = {
  OTP_PROVIDER: 'twilio',
  CAPTCHA_PROVIDER: 'recaptcha',
} as const;

async function compileApp(): Promise<unknown> {
  try {
    await Test.createTestingModule({ imports: [AppModule] }).compile();
    return undefined;
  } catch (error) {
    return error;
  }
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
    expect((error as Error).message).not.toContain('OTP_PROVIDER');
    expect((error as Error).message).not.toContain('CAPTCHA_PROVIDER');
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
