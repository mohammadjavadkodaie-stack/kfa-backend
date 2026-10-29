import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../src/audit/audit.service';
import type { RateLimitDecision, RateLimitService } from '../../src/rate-limit/rate-limit.service';
import {
  AuthService,
  type AuthRequestContext,
  type AuthResult,
  type IssuedCredentials,
  type LogoutResult,
} from '../../src/auth/auth.service';
import { InMemorySessionRepository } from '../../src/auth/in-memory-session.repository';
import type { ProofTokenService } from '../../src/auth/otp/proof-token';
import { REFRESH_COOKIE_NAME } from '../../src/auth/token/refresh-token';

/**
 * Fixtures and fakes shared by the auth service unit specs.
 *
 * Everything here is deliberately framework-neutral (no `jest` globals), so the
 * specs own the assertions while this file only owns the plumbing.
 */

export const TEST_SECRET = 'unit-test-access-token-secret-0123456789abcdef';
export const TEST_PHONE = '+14155552671';
export const TEST_OTHER_PHONE = '+14155550000';
export const TEST_USERNAME = 'ivan';
export const TEST_NOW = new Date('2026-03-01T00:00:00.000Z');

export const TEST_CONTEXT: AuthRequestContext = {
  ip: '203.0.113.7',
  deviceKey: 'device-1',
  requestId: 'req-1',
  cookieHeader: undefined,
  userAgent: 'jest-agent',
};

export const REGISTER_BODY = { proof: 'proof-1', username: TEST_USERNAME };
export const LOGIN_BODY = { proof: 'proof-1' };

export function contextWith(overrides: Partial<AuthRequestContext> = {}): AuthRequestContext {
  return { ...TEST_CONTEXT, ...overrides };
}

export function cookieContext(
  token: string,
  overrides: Partial<AuthRequestContext> = {},
): AuthRequestContext {
  return contextWith({ cookieHeader: `${REFRESH_COOKIE_NAME}=${token}`, ...overrides });
}

export interface ConsumeInput {
  readonly scope: string;
  readonly identifier: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

interface Counter {
  hits: number;
  expiresAt: number;
}

/** Same fixed-window semantics as the Redis limiter, without any Redis. */
export class FakeRateLimit {
  private readonly counters = new Map<string, Counter>();
  readonly calls: ConsumeInput[] = [];
  private now = 0;

  async consume(input: ConsumeInput): Promise<RateLimitDecision> {
    this.calls.push({ ...input });

    const key = `${input.scope}:${input.identifier}`;
    const current = this.counters.get(key);
    const counter =
      current !== undefined && current.expiresAt > this.now
        ? current
        : { hits: 0, expiresAt: this.now + input.windowSeconds * 1_000 };

    counter.hits += 1;
    this.counters.set(key, counter);

    const allowed = counter.hits <= input.limit;

    return {
      allowed,
      remaining: Math.max(0, input.limit - counter.hits),
      retryAfterSeconds: allowed ? 0 : Math.ceil((counter.expiresAt - this.now) / 1_000),
    };
  }

  seed(scope: string, identifier: string, hits: number, windowSeconds: number): void {
    this.counters.set(`${scope}:${identifier}`, {
      hits,
      expiresAt: this.now + windowSeconds * 1_000,
    });
  }

  scopes(): string[] {
    return this.calls.map((call) => call.scope);
  }
}

/** Proof store stand-in: every token resolves to the configured phone. */
export class FakeProof {
  readonly consumed: unknown[] = [];

  constructor(public phone: string | null = TEST_PHONE) {}

  async verifyAndConsumeProof(token: unknown): Promise<string | null> {
    this.consumed.push(token);

    return this.phone;
  }
}

export interface AuditRecord {
  readonly action: string;
  readonly actorId: string;
  readonly actorRole: string;
  readonly targetType: string;
  readonly targetId: string;
  readonly requestId: string;
  readonly ip: string;
  readonly metadata: Record<string, unknown>;
}

export class FakeAudit {
  readonly records: AuditRecord[] = [];

  async record(entry: AuditRecord): Promise<void> {
    this.records.push(entry);
  }
}

export class FakeLogger {
  readonly infos: unknown[] = [];
  readonly warns: unknown[] = [];

  info(entry: unknown): void {
    this.infos.push(entry);
  }

  warn(entry: unknown): void {
    this.warns.push(entry);
  }
}

export interface HarnessEnv {
  readonly ACCESS_TOKEN_SECRET?: string;
  readonly accessTokenTtlSeconds?: number;
  readonly refreshTtlDays?: number;
  readonly sessionAbsoluteDays?: number;
  readonly sessionsMaxPerUser?: number;
}

export function createHarness(env: HarnessEnv = {}) {
  const rateLimit = new FakeRateLimit();
  const proof = new FakeProof();
  const audit = new FakeAudit();
  const logger = new FakeLogger();
  const sessions = new InMemorySessionRepository();

  const service = new AuthService(
    {
      ACCESS_TOKEN_SECRET: 'ACCESS_TOKEN_SECRET' in env ? env.ACCESS_TOKEN_SECRET : TEST_SECRET,
      ACCESS_TOKEN_TTL_SECONDS: env.accessTokenTtlSeconds ?? 600,
      REFRESH_TTL_DAYS: env.refreshTtlDays ?? 14,
      SESSION_ABSOLUTE_DAYS: env.sessionAbsoluteDays ?? 30,
      SESSIONS_MAX_PER_USER: env.sessionsMaxPerUser ?? 10,
    },
    sessions,
    proof as unknown as ProofTokenService,
    rateLimit as unknown as RateLimitService,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, rateLimit, proof, audit, logger, sessions };
}

export type Harness = ReturnType<typeof createHarness>;

export function auditedActions(audit: FakeAudit): string[] {
  return audit.records.map((entry) => entry.action);
}

export function auditedMetadata(audit: FakeAudit, action: string): Record<string, unknown> {
  const entry = audit.records.find((record) => record.action === action);

  if (entry === undefined) throw new Error(`no audit record for ${action}`);

  return entry.metadata;
}

export function issued(result: AuthResult): IssuedCredentials {
  if (result.outcome !== 'issued') {
    throw new Error(`expected issued credentials, received ${result.outcome}`);
  }

  return result.credentials;
}

export function throttled(result: AuthResult | LogoutResult): number {
  if (result.outcome !== 'throttled') {
    throw new Error(`expected a throttle, received ${result.outcome}`);
  }

  return result.retryAfterSeconds;
}
