import { createHash, createHmac } from 'node:crypto';
import {
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  type OnModuleDestroy,
} from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';
import Redis, { type RedisOptions } from 'ioredis';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';

/**
 * Structurally identical to `@nestjs/throttler`'s internal
 * `ThrottlerStorageRecord`, redeclared because the package does not re-export it.
 */
export interface RateLimitRecord {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
}

/**
 * Redis-backed throttler storage that FAILS CLOSED.
 *
 * Design notes:
 * - Every counter lives in Redis under `kfa:rl:`; the tracker is HMAC-SHA256
 *   hashed with `RATE_LIMIT_HMAC_KEY` so an IP address never appears in a key
 *   and cannot be recovered by brute-forcing an unkeyed digest.
 * - All counter mutations happen in one atomic Lua script (INCR + PEXPIRE on the
 *   first hit + block handling), executed through `defineCommand` so ioredis
 *   uses EVALSHA and transparently falls back to EVAL on NOSCRIPT.
 * - Any Redis failure (down, timeout, malformed reply) results in a thrown
 *   ServiceUnavailableException: the request is denied instead of being let
 *   through. There is no in-memory fallback once Redis is configured.
 * - A missing `RATE_LIMIT_HMAC_KEY` denies too: unkeyed tracker hashes would be
 *   brute-forceable for an IP address.
 * - Commands are never retried (`maxRetriesPerRequest: 0`), are rejected while
 *   the socket is not ready and are bounded by `commandTimeout`, so a request
 *   can never wait on Redis indefinitely. Reconnects use a capped backoff.
 */

/** DI token for the shared ioredis client (absent when REDIS_URL is not set). */
export const REDIS_CLIENT = Symbol('REDIS_CLIENT');

/** Namespace for every rate-limit key written by this application. */
export const RATE_LIMIT_KEY_PREFIX = 'kfa:rl:';

/** Custom ioredis command registered on the shared client. */
const INCREMENT_COMMAND = 'incrementRateLimitWindow';

const REDIS_COMMAND_TIMEOUT_MS = 2_000;
const REDIS_CONNECT_TIMEOUT_MS = 2_000;
const REDIS_RECONNECT_BASE_DELAY_MS = 200;
const REDIS_RECONNECT_MAX_DELAY_MS = 2_000;

/**
 * INCR + PEXPIRE on the first hit + block handling, atomically.
 *
 * KEYS[1] window key, ARGV[1] limit, ARGV[2] window in ms, ARGV[3] block in ms.
 * Returns { totalHits, timeToExpire, isBlocked, timeToBlockExpire } in
 * milliseconds; `RedisThrottlerStorage` converts the two times to seconds.
 */
export const INCREMENT_RATE_LIMIT_WINDOW_SCRIPT = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local blockMs = tonumber(ARGV[3])

local totalHits = redis.call('INCR', key)
if totalHits == 1 then
  redis.call('PEXPIRE', key, windowMs)
end

local timeToExpire = redis.call('PTTL', key)
if timeToExpire < 0 then
  -- Defensive: the key lost its TTL (manual write). Never leave it unbounded.
  timeToExpire = windowMs
  redis.call('PEXPIRE', key, windowMs)
end

local isBlocked = 0
local timeToBlockExpire = 0
if totalHits > limit then
  isBlocked = 1
  -- Extend only at the first blocked hit, so retrying cannot keep the block alive.
  if totalHits == limit + 1 and blockMs > timeToExpire then
    redis.call('PEXPIRE', key, blockMs)
    timeToExpire = blockMs
  end
  timeToBlockExpire = timeToExpire
end

return { totalHits, timeToExpire, isBlocked, timeToBlockExpire }
`;

/**
 * The minimal surface both the throttler storage and `RateLimitService` need.
 * Kept as an interface so unit tests can use a hand-written fake instead of a
 * real connection.
 */
export interface RateLimitRedisClient {
  readonly status: string;
  incrementRateLimitWindow(
    key: string,
    limit: number,
    windowMs: number,
    blockMs: number,
  ): Promise<unknown>;
  quit(): Promise<unknown>;
  disconnect(): void;
}

/** Bounded connection: no lazy hangs, no unbounded per-command retries. */
export const REDIS_CLIENT_OPTIONS: RedisOptions = Object.freeze({
  // Boot never dials Redis: the first rate-limited request opens the connection.
  lazyConnect: true,
  connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
  commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
  // Never re-queue a command after a failure; the request must be denied.
  maxRetriesPerRequest: 0,
  // A command issued before the socket is ready waits, but only up to
  // `commandTimeout`, after which it is rejected (fail closed).
  enableOfflineQueue: true,
  enableReadyCheck: true,
  // Capped exponential backoff. Commands themselves are never retried, so this
  // cannot extend a request; it only decides how often to redial a dead server.
  retryStrategy: (attempt: number) =>
    Math.min(attempt * REDIS_RECONNECT_BASE_DELAY_MS, REDIS_RECONNECT_MAX_DELAY_MS),
});

/**
 * Hashes a namespace + raw value into a Redis key.
 *
 * SHA-256 is used for keyspaces (deterministic, non-reversible) and HMAC-SHA256
 * for caller-supplied trackers (see `RateLimitService` and
 * `RedisThrottlerStorage`), so a guessable tracker cannot be reversed off-line.
 */
export function buildRateLimitKey(namespace: string, value: string): string {
  const digest = createHash('sha256').update(`${namespace}:${value}`, 'utf8').digest('hex');
  return `${RATE_LIMIT_KEY_PREFIX}${namespace}:${digest}`;
}

/** Deterministic, non-reversible tracker hash. Never log the input. */
function hashTracker(value: string, hmacKey: string): string {
  return createHmac('sha256', hmacKey).update(value, 'utf8').digest('hex');
}

/**
 * Creates the shared client. The URL is never logged (pino redacts it too) and
 * no connection is opened here, so boot validation cannot depend on Redis.
 */
export function createRateLimitRedisClient(env: Pick<Env, 'REDIS_URL'>): RateLimitRedisClient {
  const url = env.REDIS_URL;

  if (url === undefined) {
    throw new Error('REDIS_URL is required to create the Redis rate-limit client');
  }

  const client = new Redis(url, REDIS_CLIENT_OPTIONS);

  client.defineCommand(INCREMENT_COMMAND, {
    numberOfKeys: 1,
    lua: INCREMENT_RATE_LIMIT_WINDOW_SCRIPT,
  });

  // An 'error' event on ioredis would otherwise crash the process. The message
  // is generic on purpose: error payloads may carry connection details.
  client.on('error', (error: Error) => {
    new Logger('RateLimitRedis').warn(`Redis rate-limit store error (${error.name})`);
  });

  return client as unknown as RateLimitRedisClient;
}

function rateLimitUnavailable(): ServiceUnavailableException {
  // Generic on purpose: callers must never learn host names, keys or values.
  return new ServiceUnavailableException();
}

function parseCounter(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

/** Validates the Lua reply before it can influence allow/deny decisions. */
export function parseRateLimitScriptReply(reply: unknown): RateLimitRecord {
  if (!Array.isArray(reply) || reply.length !== 4) {
    throw new Error('unexpected rate-limit script reply');
  }

  const totalHits = parseCounter(reply[0]);
  const timeToExpire = parseCounter(reply[1]);
  const isBlocked = parseCounter(reply[2]);
  const timeToBlockExpire = parseCounter(reply[3]);

  if (
    totalHits === undefined ||
    timeToExpire === undefined ||
    isBlocked === undefined ||
    timeToBlockExpire === undefined
  ) {
    throw new Error('unexpected rate-limit script reply');
  }

  return { totalHits, timeToExpire, isBlocked: isBlocked === 1, timeToBlockExpire };
}

@Injectable()
export class RedisThrottlerStorage implements ThrottlerStorage, OnModuleDestroy {
  private readonly hmacKey: string | undefined;
  private closing = false;

  constructor(
    @Inject(REDIS_CLIENT) private readonly client: RateLimitRedisClient | null,
    @Inject(ENV) env: Env,
  ) {
    this.hmacKey = env.RATE_LIMIT_HMAC_KEY;
  }

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): Promise<RateLimitRecord> {
    const client = this.client;
    const hmacKey = this.hmacKey;

    if (client === null || hmacKey === undefined) {
      // Fail closed: an unconfigured store must never degrade to "allow all".
      throw rateLimitUnavailable();
    }

    // HMAC so an IP tracker cannot be recovered by brute-forcing the key.
    const redisKey = buildRateLimitKey('throttle', hashTracker(`${throttlerName}:${key}`, hmacKey));

    try {
      const record = parseRateLimitScriptReply(
        await client.incrementRateLimitWindow(redisKey, limit, ttl, blockDuration),
      );

      // The script counts in ms; the guard derives Retry-After from seconds.
      return {
        totalHits: record.totalHits,
        timeToExpire: Math.ceil(record.timeToExpire / 1_000),
        isBlocked: record.isBlocked,
        timeToBlockExpire: Math.ceil(record.timeToBlockExpire / 1_000),
      };
    } catch {
      // Deliberately swallows the cause: no connection strings, host names or
      // key material may reach the client or the logs.
      throw rateLimitUnavailable();
    }
  }

  async onModuleDestroy(): Promise<void> {
    const client = this.client;

    if (client === null || this.closing) {
      return;
    }

    this.closing = true;

    try {
      // `quit` on a client that never finished a handshake (lazy or
      // reconnecting) would queue the command behind the reconnect: drop the
      // socket instead so shutdown never waits on Redis.
      if (client.status !== 'ready') {
        client.disconnect();
        return;
      }

      await client.quit();
    } catch {
      client.disconnect();
    }
  }
}
