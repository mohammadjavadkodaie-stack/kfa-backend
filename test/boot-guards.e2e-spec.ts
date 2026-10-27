import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { applyTestEnv } from './helpers/test-env';

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

  it('refuses to boot in production until a Redis throttler store is wired', async () => {
    applyTestEnv({ NODE_ENV: 'production' });

    const error = await compileApp();

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('Refusing to start');
    expect((error as Error).message).toMatch(/Redis-backed throttler store/);
  });
});
