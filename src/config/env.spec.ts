import { loadEnv } from './env';

const VALID_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: 'test',
  PORT: '4000',
  APP_ORIGINS: 'https://app.example, https://admin.example/',
  LOG_LEVEL: 'debug',
  TRUSTED_PROXY_COUNT: '1',
  BODY_LIMIT_BYTES: '2048',
};

const INVALID_CASES: Array<[string, NodeJS.ProcessEnv]> = [
  ['a missing APP_ORIGINS', {}],
  ['a wildcard origin', { APP_ORIGINS: '*' }],
  ['an origin with a path', { APP_ORIGINS: 'https://app.example/api' }],
  ['a non http(s) scheme', { APP_ORIGINS: 'ftp://app.example' }],
  ['an origin with credentials', { APP_ORIGINS: 'https://user:pass@app.example' }],
  ['an out of range port', { APP_ORIGINS: 'http://localhost:3000', PORT: '70000' }],
  ['a non numeric port', { APP_ORIGINS: 'http://localhost:3000', PORT: 'abc' }],
  ['an unknown NODE_ENV', { APP_ORIGINS: 'http://localhost:3000', NODE_ENV: 'staging' }],
  ['an unknown LOG_LEVEL', { APP_ORIGINS: 'http://localhost:3000', LOG_LEVEL: 'verbose' }],
  [
    'a body limit below the minimum',
    { APP_ORIGINS: 'http://localhost:3000', BODY_LIMIT_BYTES: '10' },
  ],
  ['a negative proxy count', { APP_ORIGINS: 'http://localhost:3000', TRUSTED_PROXY_COUNT: '-1' }],
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
    });
  });

  it('applies safe defaults for optional variables', () => {
    const env = loadEnv({ APP_ORIGINS: 'http://localhost:3000' });

    expect(env.NODE_ENV).toBe('development');
    expect(env.PORT).toBe(3000);
    expect(env.LOG_LEVEL).toBe('info');
    expect(env.TRUSTED_PROXY_COUNT).toBe(0);
    expect(env.BODY_LIMIT_BYTES).toBe(102_400);
  });

  it('deduplicates origins', () => {
    const env = loadEnv({ APP_ORIGINS: 'https://app.example,https://app.example' });

    expect(env.APP_ORIGINS).toEqual(['https://app.example']);
  });

  it.each(INVALID_CASES)('rejects %s', (_label, source) => {
    expect(() => loadEnv(source)).toThrow(/Invalid environment configuration/);
  });

  it('reports the variable name but never its value', () => {
    const sentinel = 'do-not-log-me-1234';

    expect(() => loadEnv({ APP_ORIGINS: sentinel })).toThrow(/APP_ORIGINS/);

    try {
      loadEnv({ APP_ORIGINS: sentinel });
    } catch (error) {
      expect((error as Error).message).not.toContain(sentinel);
    }
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadEnv({ APP_ORIGINS: 'http://localhost:3000' }))).toBe(true);
  });

  it('accepts production at schema level (the throttler enforces the Redis rule)', () => {
    const env = loadEnv({ APP_ORIGINS: 'https://app.example', NODE_ENV: 'production' });

    expect(env.NODE_ENV).toBe('production');
  });
});
