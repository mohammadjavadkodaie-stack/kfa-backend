/**
 * Environment used by the test suites. Values are deliberately fake/local and
 * are applied to `process.env` before a test application is compiled.
 *
 * `DATABASE_URL` is never dialled from tests: the Prisma client provider is
 * replaced in `create-test-app.ts`. It still has to be a valid URL because the
 * environment is zod-validated at boot, exactly like production.
 */
export const TEST_ENV = {
  NODE_ENV: 'test',
  PORT: '3001',
  APP_ORIGINS: 'http://localhost:3000',
  LOG_LEVEL: 'silent',
  TRUSTED_PROXY_COUNT: '0',
  BODY_LIMIT_BYTES: '1024',
  DATABASE_URL: 'postgresql://kfa_app:test-only-password@127.0.0.1:5432/kfa_test?schema=public',
  AUDIT_HMAC_KEY: 'test-only-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'test-only-rate-limit-hmac-key-0123456789',
  /** Fixed, fake key for OTP proof tokens; tests must never depend on a real secret. */
  OTP_PROOF_SECRET: 'test-only-otp-proof-secret-0123456789abcdef',
  /** Fake access-token secret; production-only validation is covered by env.spec. */
  ACCESS_TOKEN_SECRET: 'test-only-access-token-secret-0123456789abcdef',
  /**
   * Fixed, fake AES-256-GCM key: base64url of exactly 32 bytes. Production would
   * require it, but outside production it only has to be valid when present.
   */
  TOTP_ENC_KEY: 'a2ZhLXRlc3Qtb25seS10b3RwLWtleS0wMTIzNDU2Nzg',
  ACCESS_TOKEN_TTL_SECONDS: '600',
  REFRESH_TTL_DAYS: '14',
  SESSION_ABSOLUTE_DAYS: '30',
  /** Staff sessions: shorter cap, plus an idle limit checked at refresh. */
  STAFF_SESSION_ABSOLUTE_HOURS: '12',
  STAFF_SESSION_IDLE_MINUTES: '30',
  /** Low enough for a suite to reach the cap without a long login loop. */
  SESSIONS_MAX_PER_USER: '10',
  /** Small enough to hit the deployment cap in a test, large enough to be realistic. */
  OTP_GLOBAL_SENDS_PER_HOUR: '500',
  /**
   * The fake providers are the only ones wired up so far, and production
   * additionally requires non-fake values. Keeping both keys here means
   * `applyTestEnv()` also resets a value leaked from a production-env test.
   */
  OTP_PROVIDER: 'fake',
  CAPTCHA_PROVIDER: 'fake',
  /**
   * Unset by default: no test dials Redis unless it explicitly asks for it (the
   * real-Redis suite is gated by `REDIS_URL_TEST`). Keeping the key here means
   * `applyTestEnv()` also removes a leaked value between suites.
   */
  REDIS_URL: undefined,
} as const;

export type TestEnvOverrides = Partial<Record<keyof typeof TEST_ENV, string | undefined>>;

export function applyTestEnv(overrides: TestEnvOverrides = {}): void {
  const merged: Record<string, string | undefined> = { ...TEST_ENV, ...overrides };

  for (const [key, value] of Object.entries(merged)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}
