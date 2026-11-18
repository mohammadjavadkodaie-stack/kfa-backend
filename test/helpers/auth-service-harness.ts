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
import type { Role } from '../../src/auth/roles';
import { REFRESH_COOKIE_NAME } from '../../src/auth/token/refresh-token';

/**
 * Fixtures and fakes shared by the auth service unit specs.
 *
 * Everything here is deliberately framework-neutral (no `jest` globals), so the
 * specs own the assertions while this file only owns the plumbing.
 */

export const TEST_SECRET = 'unit-test-access-token-secret-0123456789abcdef';
export const TEST_EMAIL = 'ivan@example.com';
export const TEST_OTHER_EMAIL = 'other@example.com';
/** Never verified by these specs: they exercise sessions, not passwords. */
export const TEST_PASSWORD_HASH = 'scrypt$fixture$hash';
export const TEST_USERNAME = 'ivan';
export const TEST_NOW = new Date('2026-03-01T00:00:00.000Z');

export const TEST_CONTEXT: AuthRequestContext = {
  ip: '203.0.113.7',
  deviceKey: 'device-1',
  requestId: 'req-1',
  cookieHeader: undefined,
  userAgent: 'jest-agent',
};

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

/** The read-only variant: it never adds a hit, so it needs no window. */
export interface PeekInput {
  readonly scope: string;
  readonly identifier: string;
  readonly limit: number;
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
  /** When set, every `consume` denies with this retry hint, as an empty budget would. */
  private denied: number | null = null;

  /** Simulates an exhausted budget without filling any counter. */
  deny(retryAfterSeconds: number): void {
    this.denied = retryAfterSeconds;
  }

  async consume(input: ConsumeInput): Promise<RateLimitDecision> {
    this.calls.push({ ...input });

    if (this.denied !== null) {
      return { allowed: false, remaining: 0, retryAfterSeconds: this.denied };
    }

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

  /** Reads a budget without billing a hit, like `RateLimitService.peek`. */
  async peek(input: PeekInput): Promise<RateLimitDecision> {
    const counter = this.counters.get(`${input.scope}:${input.identifier}`);
    const hits = counter !== undefined && counter.expiresAt > this.now ? counter.hits : 0;

    if (hits < input.limit) {
      return { allowed: true, remaining: input.limit - hits, retryAfterSeconds: 0 };
    }

    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil(((counter?.expiresAt ?? this.now) - this.now) / 1_000),
      ),
    };
  }

  /** Forgets every window, for specs that need a second budget from scratch. */
  reset(): void {
    this.counters.clear();
    this.calls.length = 0;
    this.denied = null;
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
  /** The client each row was asked to join; `undefined` when the call had none. */
  readonly transactions: unknown[] = [];

  async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    this.transactions.push(tx);
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
  readonly staffSessionAbsoluteHours?: number;
  readonly staffSessionIdleMinutes?: number;
  readonly sessionsMaxPerUser?: number;
}

export function createHarness(env: HarnessEnv = {}) {
  const rateLimit = new FakeRateLimit();
  const audit = new FakeAudit();
  const logger = new FakeLogger();
  const sessions = new InMemorySessionRepository();

  const service = new AuthService(
    {
      ACCESS_TOKEN_SECRET: 'ACCESS_TOKEN_SECRET' in env ? env.ACCESS_TOKEN_SECRET : TEST_SECRET,
      ACCESS_TOKEN_TTL_SECONDS: env.accessTokenTtlSeconds ?? 600,
      REFRESH_TTL_DAYS: env.refreshTtlDays ?? 14,
      SESSION_ABSOLUTE_DAYS: env.sessionAbsoluteDays ?? 30,
      STAFF_SESSION_ABSOLUTE_HOURS: env.staffSessionAbsoluteHours ?? 12,
      STAFF_SESSION_IDLE_MINUTES: env.staffSessionIdleMinutes ?? 30,
      SESSIONS_MAX_PER_USER: env.sessionsMaxPerUser ?? 10,
    },
    sessions,
    rateLimit as unknown as RateLimitService,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, rateLimit, audit, logger, sessions };
}

export type Harness = ReturnType<typeof createHarness>;

export interface FixtureIdentity {
  readonly email?: string;
  readonly username?: string;
}

/**
 * The same first session the email sign-up issues, without the proof, the
 * password policy or an HTTP round trip: those belong to the email specs.
 */
export async function registerFixture(
  harness: Harness,
  context: AuthRequestContext = TEST_CONTEXT,
  identity: FixtureIdentity = {},
): Promise<AuthResult> {
  return harness.service.issueEmailAccountSession({
    email: identity.email ?? TEST_EMAIL,
    username: identity.username ?? TEST_USERNAME,
    passwordHash: TEST_PASSWORD_HASH,
    context,
  });
}

/** A new session for an account that already exists. */
export async function loginFixture(
  harness: Harness,
  account: { readonly id: string; readonly role: Role },
  context: AuthRequestContext = TEST_CONTEXT,
): Promise<AuthResult> {
  return harness.service.issueEmailLoginSession({ email: TEST_EMAIL, account, context });
}

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
