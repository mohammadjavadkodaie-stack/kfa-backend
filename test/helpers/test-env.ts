/**
 * Environment used by the test suites. Values are deliberately fake/local and
 * are applied to `process.env` before a test application is compiled.
 */
export const TEST_ENV = {
  NODE_ENV: 'test',
  PORT: '3001',
  APP_ORIGINS: 'http://localhost:3000',
  LOG_LEVEL: 'silent',
  TRUSTED_PROXY_COUNT: '0',
  BODY_LIMIT_BYTES: '1024',
} as const;

export type TestEnvOverrides = Partial<Record<keyof typeof TEST_ENV, string>>;

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
