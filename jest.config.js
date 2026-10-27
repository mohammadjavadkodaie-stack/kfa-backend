/**
 * Unit tests (`pnpm test`).
 *
 * NestJS 12 is published as ESM only, so Jest must be able to `require()` ESM
 * packages from the CommonJS test files. That path needs Node's VM modules
 * (`--experimental-vm-modules`), which the `test` script passes explicitly -
 * without it Jest fails with "Must use import to load ES Module".
 *
 * @type {import('jest').Config}
 */
module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '.',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/src/**/*.spec.ts'],
  setupFiles: ['reflect-metadata'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }],
  },
  clearMocks: true,
  collectCoverageFrom: ['src/**/*.ts', '!src/main.ts', '!src/**/*.module.ts'],
  coverageDirectory: 'coverage',
};
