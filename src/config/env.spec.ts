import { loadEnv } from './env';

const BASE_ENV: NodeJS.ProcessEnv = {
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:app-secret@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
};

const VALID_ENV: NodeJS.ProcessEnv = {
  ...BASE_ENV,
  NODE_ENV: 'test',
  PORT: '4000',
  APP_ORIGINS: 'https://app.example, https://admin.example/',
  LOG_LEVEL: 'debug',
  TRUSTED_PROXY_COUNT: '1',
  BODY_LIMIT_BYTES: '2048',
};

const INVALID_CASES: Array<[string, NodeJS.ProcessEnv]> = [
  ['a missing APP_ORIGINS', { ...BASE_ENV, APP_ORIGINS: undefined }],
  ['a wildcard origin', { ...BASE_ENV, APP_ORIGINS: '*' }],
  ['an origin with a path', { ...BASE_ENV, APP_ORIGINS: 'https://app.example/api' }],
  ['a non http(s) scheme', { ...BASE_ENV, APP_ORIGINS: 'ftp://app.example' }],
  ['an origin with credentials', { ...BASE_ENV, APP_ORIGINS: 'https://user:pass@app.example' }],
  ['an out of range port', { ...BASE_ENV, PORT: '70000' }],
  ['a non numeric port', { ...BASE_ENV, PORT: 'abc' }],
  ['an unknown NODE_ENV', { ...BASE_ENV, NODE_ENV: 'staging' }],
  ['an unknown LOG_LEVEL', { ...BASE_ENV, LOG_LEVEL: 'verbose' }],
  ['a body limit below the minimum', { ...BASE_ENV, BODY_LIMIT_BYTES: '10' }],
  ['a negative proxy count', { ...BASE_ENV, TRUSTED_PROXY_COUNT: '-1' }],
  ['a missing DATABASE_URL', { ...BASE_ENV, DATABASE_URL: undefined }],
  ['a non postgres DATABASE_URL', { ...BASE_ENV, DATABASE_URL: 'mysql://u:p@db:3306/kfa' }],
  ['a DATABASE_URL without a user', { ...BASE_ENV, DATABASE_URL: 'postgresql://db:5432/kfa' }],
  ['a DATABASE_URL without a database', { ...BASE_ENV, DATABASE_URL: 'postgresql://u:p@db:5432' }],
  ['a DATABASE_URL with a fragment', { ...BASE_ENV, DATABASE_URL: 'postgresql://u:p@db/kfa#x' }],
  ['an invalid MIGRATION_DATABASE_URL', { ...BASE_ENV, MIGRATION_DATABASE_URL: 'not-a-url' }],
  ['a missing AUDIT_HMAC_KEY', { ...BASE_ENV, AUDIT_HMAC_KEY: undefined }],
  ['a short AUDIT_HMAC_KEY', { ...BASE_ENV, AUDIT_HMAC_KEY: 'too-short' }],
];

describe('loadEnv', () => {
  it('parses a valid environment', () => {
    expect(loadEnv({ ...VALID_ENV })).toEqual({
      NODE_ENV: 'test',
      PORT: 4000,
      APP_ORIGINS: ['https://app.example', 'https://admin.example'],
      LOG_LEVEL: 'debug',
      TRUSTED_PROXY_COUNT: 1,
      BODY_LIMIT_BYTES: 2048,
      DATABASE_URL: 'postgresql://kfa_app:app-secret@127.0.0.1:5432/kfa?schema=public',
      AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
    });
  });

  it('applies safe defaults for optional variables', () => {
    const env = loadEnv({ ...BASE_ENV });

    expect(env.NODE_ENV).toBe('development');
    expect(env.PORT).toBe(3000);
    expect(env.LOG_LEVEL).toBe('info');
    expect(env.TRUSTED_PROXY_COUNT).toBe(0);
    expect(env.BODY_LIMIT_BYTES).toBe(102_400);
    expect(env.MIGRATION_DATABASE_URL).toBeUndefined();
  });

  it('deduplicates origins', () => {
    const env = loadEnv({
      ...BASE_ENV,
      APP_ORIGINS: 'https://app.example,https://app.example',
    });

    expect(env.APP_ORIGINS).toEqual(['https://app.example']);
  });

  it.each(INVALID_CASES)('rejects %s', (_label, source) => {
    expect(() => loadEnv(source)).toThrow(/Invalid environment configuration/);
  });

  it('reports the variable name but never its value', () => {
    const sentinel = 'do-not-log-me-1234';

    expect(() => loadEnv({ ...BASE_ENV, APP_ORIGINS: sentinel })).toThrow(/APP_ORIGINS/);

    try {
      loadEnv({ ...BASE_ENV, APP_ORIGINS: sentinel });
    } catch (error) {
      expect((error as Error).message).not.toContain(sentinel);
    }
  });

  it('never echoes a database password in validation errors', () => {
    const password = 'super-secret-db-password';

    try {
      loadEnv({
        ...BASE_ENV,
        NODE_ENV: 'production',
        DATABASE_URL: `postgresql://kfa_app:${password}@db.internal:5432/kfa?sslmode=disable`,
      });
      throw new Error('expected loadEnv to reject a non-TLS production URL');
    } catch (error) {
      expect((error as Error).message).toContain('DATABASE_URL');
      expect((error as Error).message).not.toContain(password);
    }
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadEnv({ ...BASE_ENV }))).toBe(true);
  });

  it('requires TLS for database URLs in production', () => {
    expect(() =>
      loadEnv({ ...BASE_ENV, NODE_ENV: 'production', DATABASE_URL: 'postgresql://u:p@db/kfa' }),
    ).toThrow(/DATABASE_URL.*sslmode=require/);

    const env = loadEnv({
      ...BASE_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=verify-full',
      MIGRATION_DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=require',
    });

    expect(env.NODE_ENV).toBe('production');
  });

  it('requires TLS for MIGRATION_DATABASE_URL in production', () => {
    expect(() =>
      loadEnv({
        ...BASE_ENV,
        NODE_ENV: 'production',
        DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=require',
        MIGRATION_DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=disable',
      }),
    ).toThrow(/MIGRATION_DATABASE_URL.*sslmode=require/);
  });

  it('accepts an sslmode from the connection string case-insensitively', () => {
    const env = loadEnv({
      ...BASE_ENV,
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=REQUIRE',
    });

    expect(env.DATABASE_URL).toContain('sslmode=REQUIRE');
  });

  it('accepts production at schema level once TLS is configured', () => {
    const env = loadEnv({
      ...BASE_ENV,
      APP_ORIGINS: 'https://app.example',
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=require',
    });

    expect(env.NODE_ENV).toBe('production');
  });
});
