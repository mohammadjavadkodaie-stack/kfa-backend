import { loadEnv } from './env';

const BASE_ENV: NodeJS.ProcessEnv = {
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:app-secret@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
  OTP_PROOF_SECRET: 'unit-test-otp-proof-secret-0123456789abcdef',
  ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
  OTP_PROVIDER: 'fake',
  CAPTCHA_PROVIDER: 'fake',
};

const VALID_ENV: NodeJS.ProcessEnv = {
  ...BASE_ENV,
  NODE_ENV: 'test',
  PORT: '4000',
  APP_ORIGINS: 'https://app.example, https://admin.example/',
  LOG_LEVEL: 'debug',
  TRUSTED_PROXY_COUNT: '1',
  BODY_LIMIT_BYTES: '2048',
  REDIS_URL: 'redis://:dev-only-change-me@127.0.0.1:6380/0',
};

const PROD_REDIS_URL = 'rediss://:prod-only-redis-password@redis.internal:6380/0';

/** Fixed, fake AES key: base64url of exactly 32 bytes (decodes to "kfa-unit-test-..."). */
const PROD_TOTP_ENC_KEY = 'a2ZhLXVuaXQtdGVzdC10b3RwLWVuYy1rZXktMTIzNDU';

/** A production environment that satisfies every production-only rule. */
const PROD_ENV: NodeJS.ProcessEnv = {
  ...BASE_ENV,
  NODE_ENV: 'production',
  APP_ORIGINS: 'https://app.example',
  DATABASE_URL: 'postgresql://kfa_app:app-secret@db.internal:5432/kfa?sslmode=require',
  REDIS_URL: PROD_REDIS_URL,
  TOTP_ENC_KEY: PROD_TOTP_ENC_KEY,
  OTP_PROVIDER: 'twilio',
  CAPTCHA_PROVIDER: 'recaptcha',
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
  ['an unparsable REDIS_URL', { ...BASE_ENV, REDIS_URL: 'not-a-url' }],
  ['a non redis REDIS_URL', { ...BASE_ENV, REDIS_URL: 'https://redis.internal:6380' }],
  ['a REDIS_URL with a fragment', { ...BASE_ENV, REDIS_URL: 'redis://:secret@redis:6380/0#x' }],
  ['a short RATE_LIMIT_HMAC_KEY', { ...BASE_ENV, RATE_LIMIT_HMAC_KEY: 'too-short' }],
  ['a missing REDIS_URL in production', { ...PROD_ENV, REDIS_URL: undefined }],
  [
    'a plaintext REDIS_URL in production',
    { ...PROD_ENV, REDIS_URL: 'redis://:prod-only-redis-password@redis.internal:6380/0' },
  ],
  [
    'a REDIS_URL without a password in production',
    { ...PROD_ENV, REDIS_URL: 'rediss://redis.internal:6380/0' },
  ],
  ['a missing RATE_LIMIT_HMAC_KEY in production', { ...PROD_ENV, RATE_LIMIT_HMAC_KEY: undefined }],
  ['a short OTP_PROOF_SECRET', { ...BASE_ENV, OTP_PROOF_SECRET: 'too-short' }],
  [
    'an OTP_PROOF_SECRET equal to the audit key',
    { ...BASE_ENV, OTP_PROOF_SECRET: 'unit-test-audit-hmac-key-0123456789' },
  ],
  [
    'an OTP_PROOF_SECRET equal to the rate-limit key',
    { ...BASE_ENV, OTP_PROOF_SECRET: 'unit-test-rate-limit-hmac-key-0123456789' },
  ],
  ['a missing OTP_PROOF_SECRET in production', { ...PROD_ENV, OTP_PROOF_SECRET: undefined }],
  [
    'a TOTP_ENC_KEY that is not base64url',
    { ...BASE_ENV, TOTP_ENC_KEY: 'not+a+valid+base64url+value+here' },
  ],
  [
    'a TOTP_ENC_KEY of the wrong decoded length',
    { ...BASE_ENV, TOTP_ENC_KEY: Buffer.alloc(31, 7).toString('base64url') },
  ],
  ['a missing TOTP_ENC_KEY in production', { ...PROD_ENV, TOTP_ENC_KEY: undefined }],
  ['an OTP send cap of zero', { ...BASE_ENV, OTP_GLOBAL_SENDS_PER_HOUR: '0' }],
  ['a non numeric OTP send cap', { ...BASE_ENV, OTP_GLOBAL_SENDS_PER_HOUR: 'many' }],
  ['a short ACCESS_TOKEN_SECRET', { ...BASE_ENV, ACCESS_TOKEN_SECRET: 'too-short' }],
  [
    'an ACCESS_TOKEN_SECRET equal to the audit key',
    { ...BASE_ENV, ACCESS_TOKEN_SECRET: 'unit-test-audit-hmac-key-0123456789' },
  ],
  [
    'an ACCESS_TOKEN_SECRET equal to the rate-limit key',
    { ...BASE_ENV, ACCESS_TOKEN_SECRET: 'unit-test-rate-limit-hmac-key-0123456789' },
  ],
  [
    'an ACCESS_TOKEN_SECRET equal to the proof secret',
    { ...BASE_ENV, ACCESS_TOKEN_SECRET: 'unit-test-otp-proof-secret-0123456789abcdef' },
  ],
  ['a missing ACCESS_TOKEN_SECRET in production', { ...PROD_ENV, ACCESS_TOKEN_SECRET: undefined }],
  ['an access-token TTL below one minute', { ...BASE_ENV, ACCESS_TOKEN_TTL_SECONDS: '59' }],
  ['an access-token TTL above fifteen minutes', { ...BASE_ENV, ACCESS_TOKEN_TTL_SECONDS: '901' }],
  ['a refresh TTL of zero days', { ...BASE_ENV, REFRESH_TTL_DAYS: '0' }],
  ['an absolute session cap of zero days', { ...BASE_ENV, SESSION_ABSOLUTE_DAYS: '0' }],
  ['a staff absolute lifetime of zero hours', { ...BASE_ENV, STAFF_SESSION_ABSOLUTE_HOURS: '0' }],
  ['a negative staff absolute lifetime', { ...BASE_ENV, STAFF_SESSION_ABSOLUTE_HOURS: '-2' }],
  ['a non numeric staff absolute lifetime', { ...BASE_ENV, STAFF_SESSION_ABSOLUTE_HOURS: '12h' }],
  [
    'a staff lifetime above the normal cap',
    { ...BASE_ENV, SESSION_ABSOLUTE_DAYS: '1', STAFF_SESSION_ABSOLUTE_HOURS: '25' },
  ],
  ['a staff idle limit of zero minutes', { ...BASE_ENV, STAFF_SESSION_IDLE_MINUTES: '0' }],
  ['a negative staff idle limit', { ...BASE_ENV, STAFF_SESSION_IDLE_MINUTES: '-5' }],
  [
    'a staff idle limit above the staff lifetime',
    { ...BASE_ENV, STAFF_SESSION_IDLE_MINUTES: '721' },
  ],
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
      OTP_PROVIDER: 'fake',
      CAPTCHA_PROVIDER: 'fake',
      DATABASE_URL: 'postgresql://kfa_app:app-secret@127.0.0.1:5432/kfa?schema=public',
      AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
      REDIS_URL: 'redis://:dev-only-change-me@127.0.0.1:6380/0',
      RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
      OTP_PROOF_SECRET: 'unit-test-otp-proof-secret-0123456789abcdef',
      OTP_GLOBAL_SENDS_PER_HOUR: 500,
      ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
      ACCESS_TOKEN_TTL_SECONDS: 600,
      REFRESH_TTL_DAYS: 14,
      SESSION_ABSOLUTE_DAYS: 30,
      STAFF_SESSION_ABSOLUTE_HOURS: 12,
      STAFF_SESSION_IDLE_MINUTES: 30,
      SESSIONS_MAX_PER_USER: 10,
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

  it('treats the shared Redis store and its HMAC key as optional outside production', () => {
    const env = loadEnv({ ...BASE_ENV });

    expect(env.REDIS_URL).toBeUndefined();
    expect(env.RATE_LIMIT_HMAC_KEY).toBe('unit-test-rate-limit-hmac-key-0123456789');
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
        ...PROD_ENV,
        DATABASE_URL: `postgresql://kfa_app:${password}@db.internal:5432/kfa?sslmode=disable`,
      });
      throw new Error('expected loadEnv to reject a non-TLS production URL');
    } catch (error) {
      expect((error as Error).message).toContain('DATABASE_URL');
      expect((error as Error).message).not.toContain(password);
    }
  });

  it('never echoes a Redis password in validation errors', () => {
    const password = 'super-secret-redis-password';

    try {
      loadEnv({ ...PROD_ENV, REDIS_URL: `redis://:${password}@redis.internal:6380/0` });
      throw new Error('expected loadEnv to reject a plaintext production Redis URL');
    } catch (error) {
      expect((error as Error).message).toContain('REDIS_URL');
      expect((error as Error).message).not.toContain(password);
    }
  });

  it('requires a shared, TLS-protected Redis store in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, REDIS_URL: undefined })).toThrow(
      /REDIS_URL.*required in production/,
    );
    expect(() =>
      loadEnv({ ...PROD_ENV, REDIS_URL: 'redis://:prod-only-redis-password@redis:6380/0' }),
    ).toThrow(/REDIS_URL.*rediss/);
    expect(() => loadEnv({ ...PROD_ENV, REDIS_URL: 'rediss://redis:6380/0' })).toThrow(
      /REDIS_URL.*password/,
    );
  });

  it('requires a rate-limit HMAC key in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, RATE_LIMIT_HMAC_KEY: undefined })).toThrow(
      /RATE_LIMIT_HMAC_KEY/,
    );
  });

  it('requires an OTP proof secret in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, OTP_PROOF_SECRET: undefined })).toThrow(
      /OTP_PROOF_SECRET.*required in production/,
    );
  });

  it('never allows the proof secret to double as another HMAC key', () => {
    expect(() =>
      loadEnv({ ...PROD_ENV, OTP_PROOF_SECRET: PROD_ENV.AUDIT_HMAC_KEY as string }),
    ).toThrow(/OTP_PROOF_SECRET.*must differ/);
    expect(() =>
      loadEnv({ ...PROD_ENV, OTP_PROOF_SECRET: PROD_ENV.RATE_LIMIT_HMAC_KEY as string }),
    ).toThrow(/OTP_PROOF_SECRET.*must differ/);
    expect(() => loadEnv({ ...PROD_ENV })).not.toThrow();
  });

  it('keeps the TOTP encryption key optional outside production', () => {
    expect(loadEnv({ ...BASE_ENV }).TOTP_ENC_KEY).toBeUndefined();
    expect(loadEnv({ ...BASE_ENV, TOTP_ENC_KEY: PROD_TOTP_ENC_KEY }).TOTP_ENC_KEY).toBe(
      PROD_TOTP_ENC_KEY,
    );
  });

  it('requires a 32-byte TOTP encryption key in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, TOTP_ENC_KEY: undefined })).toThrow(
      /TOTP_ENC_KEY.*required in production/,
    );
    expect(() => loadEnv({ ...PROD_ENV, TOTP_ENC_KEY: 'too-short' })).toThrow(/TOTP_ENC_KEY/);
    expect(() =>
      loadEnv({ ...PROD_ENV, TOTP_ENC_KEY: Buffer.alloc(32, 1).toString('base64') }),
    ).toThrow(/TOTP_ENC_KEY/);
    expect(() => loadEnv({ ...PROD_ENV })).not.toThrow();
  });

  it('never allows the TOTP key to double as another secret', () => {
    expect(() => loadEnv({ ...PROD_ENV, AUDIT_HMAC_KEY: PROD_TOTP_ENC_KEY })).toThrow(
      /TOTP_ENC_KEY.*must differ/,
    );
    expect(() => loadEnv({ ...PROD_ENV, OTP_PROOF_SECRET: PROD_TOTP_ENC_KEY })).toThrow(
      /TOTP_ENC_KEY.*must differ/,
    );
  });

  it('never echoes the TOTP encryption key', () => {
    const value = 'do-not-log-this-totp-key-0123456789';

    try {
      loadEnv({ ...PROD_ENV, TOTP_ENC_KEY: value });
      throw new Error('expected loadEnv to reject a malformed TOTP key');
    } catch (error) {
      expect((error as Error).message).toContain('TOTP_ENC_KEY');
      expect((error as Error).message).not.toContain(value);
    }
  });

  it('caps OTP sends per hour with a conservative default', () => {
    expect(loadEnv({ ...BASE_ENV }).OTP_GLOBAL_SENDS_PER_HOUR).toBe(500);
    expect(
      loadEnv({ ...BASE_ENV, OTP_GLOBAL_SENDS_PER_HOUR: '25' }).OTP_GLOBAL_SENDS_PER_HOUR,
    ).toBe(25);
  });

  it('defaults session lifetimes to short access tokens and bounded sessions', () => {
    const env = loadEnv({ ...BASE_ENV });

    expect(env.ACCESS_TOKEN_TTL_SECONDS).toBe(600);
    expect(env.REFRESH_TTL_DAYS).toBe(14);
    expect(env.SESSION_ABSOLUTE_DAYS).toBe(30);
    expect(env.STAFF_SESSION_ABSOLUTE_HOURS).toBe(12);
    expect(env.STAFF_SESSION_IDLE_MINUTES).toBe(30);
  });

  it('accepts a staff lifetime equal to the normal cap and an idle limit equal to it', () => {
    const env = loadEnv({
      ...BASE_ENV,
      SESSION_ABSOLUTE_DAYS: '1',
      STAFF_SESSION_ABSOLUTE_HOURS: '24',
      STAFF_SESSION_IDLE_MINUTES: '1440',
    });

    expect(env.STAFF_SESSION_ABSOLUTE_HOURS).toBe(24);
    expect(env.STAFF_SESSION_IDLE_MINUTES).toBe(1_440);
  });

  it('caps active sessions per user between 1 and 50', () => {
    expect(loadEnv({ ...BASE_ENV }).SESSIONS_MAX_PER_USER).toBe(10);
    expect(loadEnv({ ...BASE_ENV, SESSIONS_MAX_PER_USER: '1' }).SESSIONS_MAX_PER_USER).toBe(1);
    expect(loadEnv({ ...BASE_ENV, SESSIONS_MAX_PER_USER: '50' }).SESSIONS_MAX_PER_USER).toBe(50);
    expect(() => loadEnv({ ...BASE_ENV, SESSIONS_MAX_PER_USER: '0' })).toThrow(
      /SESSIONS_MAX_PER_USER/,
    );
    expect(() => loadEnv({ ...BASE_ENV, SESSIONS_MAX_PER_USER: '51' })).toThrow(
      /SESSIONS_MAX_PER_USER/,
    );
  });

  it('treats the access-token secret as optional outside production', () => {
    const env = loadEnv({ ...BASE_ENV, ACCESS_TOKEN_SECRET: undefined });

    expect(env.ACCESS_TOKEN_SECRET).toBeUndefined();
  });

  it('requires an independent access-token secret in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, ACCESS_TOKEN_SECRET: undefined })).toThrow(
      /ACCESS_TOKEN_SECRET.*required in production/,
    );
    expect(() =>
      loadEnv({ ...PROD_ENV, ACCESS_TOKEN_SECRET: PROD_ENV.AUDIT_HMAC_KEY as string }),
    ).toThrow(/ACCESS_TOKEN_SECRET.*must differ/);
    expect(() => loadEnv({ ...PROD_ENV })).not.toThrow();
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadEnv({ ...BASE_ENV }))).toBe(true);
  });

  it('rejects fake OTP and CAPTCHA providers in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, OTP_PROVIDER: 'fake', CAPTCHA_PROVIDER: 'fake' })).toThrow(
      /OTP_PROVIDER|CAPTCHA_PROVIDER/,
    );
    expect(() =>
      loadEnv({ ...PROD_ENV, OTP_PROVIDER: 'twilio', CAPTCHA_PROVIDER: 'recaptcha' }),
    ).not.toThrow();
  });

  it('requires TLS for database URLs in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, DATABASE_URL: 'postgresql://u:p@db/kfa' })).toThrow(
      /DATABASE_URL.*sslmode=require/,
    );

    const env = loadEnv({
      ...PROD_ENV,
      DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=verify-full',
      MIGRATION_DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=require',
    });

    expect(env.NODE_ENV).toBe('production');
  });

  it('requires TLS for MIGRATION_DATABASE_URL in production', () => {
    expect(() =>
      loadEnv({
        ...PROD_ENV,
        MIGRATION_DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=disable',
      }),
    ).toThrow(/MIGRATION_DATABASE_URL.*sslmode=require/);
  });

  it('accepts an sslmode from the connection string case-insensitively', () => {
    const env = loadEnv({
      ...PROD_ENV,
      DATABASE_URL: 'postgresql://u:p@db/kfa?sslmode=REQUIRE',
    });

    expect(env.DATABASE_URL).toContain('sslmode=REQUIRE');
  });

  it('accepts production once TLS databases and a Redis store are configured', () => {
    const env = loadEnv({ ...PROD_ENV });

    expect(env.NODE_ENV).toBe('production');
    expect(env.REDIS_URL).toBe(PROD_REDIS_URL);
  });
});
