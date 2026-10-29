import { createHmac } from 'node:crypto';
import {
  BadRequestException,
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import {
  buildRateLimitKey,
  parseRateLimitScriptReply,
  REDIS_CLIENT,
  type RateLimitRedisClient,
} from './redis-throttler.storage';

/** A single limit that must be enforced by the shared Redis store. */
export interface ConsumeRateLimitInput {
  /** Logical bucket, e.g. `login` or `otp-send`. Becomes part of the key. */
  readonly scope: string;
  /** Raw tracker: IP address, phone number, user id... It is never stored raw. */
  readonly identifier: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  /** Hits left in the current window (never negative). */
  readonly remaining: number;
  /** Seconds the caller must wait before retrying; 0 when allowed. */
  readonly retryAfterSeconds: number;
}

/** Minimal input for clearing a counter (e.g. after a successful login). */
export interface ResetRateLimitInput {
  readonly scope: string;
  readonly identifier: string;
}

const MAX_SCOPE_LENGTH = 64;
const MAX_IDENTIFIER_LENGTH = 256;

function rateLimitUnavailable(): ServiceUnavailableException {
  // Generic on purpose: never leak Redis hosts, keys or identifiers.
  return new ServiceUnavailableException();
}

/**
 * Redis-backed fixed-window rate limiting for endpoints that need an explicit
 * check in addition to the global `ThrottlerGuard` (login, OTP, ...).
 *
 * Fail-closed rules:
 * - No Redis client (REDIS_URL missing outside production) -> 503.
 * - No HMAC key -> 503 (an unkeyed hash would be brute-forceable).
 * - Any Redis error or malformed reply -> 503.
 *
 * Identifiers are HMAC-SHA256 hashed with `RATE_LIMIT_HMAC_KEY` so raw IPs and
 * phone numbers never reach Redis keys, logs or error messages.
 */
@Injectable()
export class RateLimitService {
  private readonly hmacKey: string | undefined;

  constructor(
    @Inject(REDIS_CLIENT) private readonly client: RateLimitRedisClient | null,
    @Inject(ENV) env: Env,
  ) {
    this.hmacKey = env.RATE_LIMIT_HMAC_KEY;
  }

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    const { scope, identifier, limit, windowSeconds } = input;

    if (
      typeof scope !== 'string' ||
      scope.length === 0 ||
      scope.length > MAX_SCOPE_LENGTH ||
      typeof identifier !== 'string' ||
      identifier.length === 0 ||
      identifier.length > MAX_IDENTIFIER_LENGTH ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      !Number.isInteger(windowSeconds) ||
      windowSeconds < 1
    ) {
      throw new BadRequestException();
    }

    const client = this.client;
    const hmacKey = this.hmacKey;

    if (client === null || hmacKey === undefined) {
      throw rateLimitUnavailable();
    }

    const key = buildRateLimitKey(
      'consume',
      `${scope}:${this.hashIdentifier(identifier, hmacKey)}`,
    );

    try {
      const record = parseRateLimitScriptReply(
        await client.incrementRateLimitWindow(key, limit, windowSeconds * 1_000, 0),
      );

      return {
        allowed: !record.isBlocked,
        remaining: Math.max(0, limit - record.totalHits),
        retryAfterSeconds: record.isBlocked
          ? Math.max(0, Math.ceil(record.timeToBlockExpire / 1_000))
          : 0,
      };
    } catch {
      // Fail closed: an unreachable store must deny, never allow.
      throw rateLimitUnavailable();
    }
  }

  /**
   * Clears a counter, so a successful attempt is not billed against the budget
   * of a failed one (e.g. OTP mismatches before the right code).
   *
   * Fails closed like `consume`: a Redis outage must not silently keep a lock
   * the caller believes is gone.
   */
  async reset(input: ResetRateLimitInput): Promise<void> {
    const { scope, identifier } = input;

    if (
      typeof scope !== 'string' ||
      scope.length === 0 ||
      scope.length > MAX_SCOPE_LENGTH ||
      typeof identifier !== 'string' ||
      identifier.length === 0 ||
      identifier.length > MAX_IDENTIFIER_LENGTH
    ) {
      throw new BadRequestException();
    }

    const client = this.client;
    const hmacKey = this.hmacKey;

    if (client === null || hmacKey === undefined) {
      throw rateLimitUnavailable();
    }

    const key = buildRateLimitKey(
      'consume',
      `${scope}:${this.hashIdentifier(identifier, hmacKey)}`,
    );

    try {
      await client.del(key);
    } catch {
      throw rateLimitUnavailable();
    }
  }

  /** Deterministic, non-reversible tracker hash. Never log the input. */
  private hashIdentifier(identifier: string, hmacKey: string): string {
    return createHmac('sha256', hmacKey).update(identifier, 'utf8').digest('hex');
  }
}
