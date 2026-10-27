import { ServiceUnavailableException } from '@nestjs/common';
import {
  buildRateLimitKey,
  createRateLimitRedisClient,
  parseRateLimitScriptReply,
  RATE_LIMIT_KEY_PREFIX,
  REDIS_CLIENT_OPTIONS,
  RedisThrottlerStorage,
  type RateLimitRedisClient,
} from './redis-throttler.storage';

const RAW_IP = '203.0.113.7';
const TTL_MS = 60_000;
const LIMIT = 5;

interface Harness {
  storage: RedisThrottlerStorage;
  client: {
    status: string;
    incrementRateLimitWindow: jest.Mock;
    quit: jest.Mock;
    disconnect: jest.Mock;
  };
}

function createHarness(): Harness {
  const client = {
    status: 'ready',
    incrementRateLimitWindow: jest.fn(),
    quit: jest.fn().mockResolvedValue('OK'),
    disconnect: jest.fn(),
  };

  const storage = new RedisThrottlerStorage(client as unknown as RateLimitRedisClient);

  return { storage, client };
}

describe('RedisThrottlerStorage.increment', () => {
  it('hashes the key under the kfa:rl prefix and never stores the raw tracker', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([1, TTL_MS, 0, 0]);

    await storage.increment(RAW_IP, TTL_MS, LIMIT, 0, 'default');

    const [key] = client.incrementRateLimitWindow.mock.calls[0] as [string, number, number, number];

    expect(key).toMatch(new RegExp(`^${RATE_LIMIT_KEY_PREFIX}throttle:[0-9a-f]{64}$`));
    expect(key).not.toContain(RAW_IP);
  });

  it('passes the window and block duration through to Redis in milliseconds', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([2, 30_000, 0, 0]);

    await storage.increment('tracker', TTL_MS, LIMIT, 120_000, 'default');

    const [, limit, ttl, blockDuration] = client.incrementRateLimitWindow.mock.calls[0] as [
      string,
      number,
      number,
      number,
    ];

    expect({ limit, ttl, blockDuration }).toEqual({
      limit: LIMIT,
      ttl: TTL_MS,
      blockDuration: 120_000,
    });
  });

  it('returns the normalized record for an allowed request', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([3, 12_345, 0, 0]);

    await expect(storage.increment('tracker', TTL_MS, LIMIT, 0, 'default')).resolves.toEqual({
      totalHits: 3,
      timeToExpire: 12_345,
      isBlocked: false,
      timeToBlockExpire: 0,
    });
  });

  it('flags a blocked request', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([6, 30_000, 1, 30_000]);

    await expect(storage.increment('tracker', TTL_MS, LIMIT, 30_000, 'default')).resolves.toEqual({
      totalHits: 6,
      timeToExpire: 30_000,
      isBlocked: true,
      timeToBlockExpire: 30_000,
    });
  });

  it('fails closed when no Redis client is configured', async () => {
    const storage = new RedisThrottlerStorage(null);

    await expect(storage.increment('tracker', TTL_MS, LIMIT, 0, 'default')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('fails closed with a generic error when Redis rejects the command', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockRejectedValue(
      new Error('connect ECONNREFUSED redis://default:secret@10.0.0.5:6379'),
    );

    const error = await storage
      .increment(RAW_IP, TTL_MS, LIMIT, 0, 'default')
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expect((error as ServiceUnavailableException).getStatus()).toBe(503);
    expect((error as ServiceUnavailableException).message).toBe('Service Unavailable');
    expect(JSON.stringify((error as Error).message)).not.toContain('10.0.0.5');
    expect(JSON.stringify((error as Error).message)).not.toContain(RAW_IP);
  });

  it('fails closed when the script reply is malformed', async () => {
    const { storage, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue(['not-a-number', 1, 0, 0]);

    await expect(storage.increment('tracker', TTL_MS, LIMIT, 0, 'default')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });
});

describe('RedisThrottlerStorage.onModuleDestroy', () => {
  it('closes a connected client with QUIT', async () => {
    const { storage, client } = createHarness();

    await storage.onModuleDestroy();

    expect(client.quit).toHaveBeenCalledTimes(1);
    expect(client.disconnect).not.toHaveBeenCalled();
  });

  it('never dials a lazy client that was never used', async () => {
    const { storage, client } = createHarness();

    client.status = 'wait';

    await storage.onModuleDestroy();

    expect(client.quit).not.toHaveBeenCalled();
    expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  it('falls back to DISCONNECT when QUIT fails and is idempotent', async () => {
    const { storage, client } = createHarness();

    client.quit.mockRejectedValue(new Error('socket closed'));

    await storage.onModuleDestroy();
    await storage.onModuleDestroy();

    expect(client.quit).toHaveBeenCalledTimes(1);
    expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  it('is a no-op without a client', async () => {
    await expect(new RedisThrottlerStorage(null).onModuleDestroy()).resolves.toBeUndefined();
  });
});

describe('buildRateLimitKey', () => {
  it('is deterministic, namespaced and prefix-scoped', () => {
    const first = buildRateLimitKey('throttle', 'default:203.0.113.7');
    const second = buildRateLimitKey('throttle', 'default:203.0.113.7');

    expect(first).toBe(second);
    expect(first.startsWith(`${RATE_LIMIT_KEY_PREFIX}throttle:`)).toBe(true);
    expect(first).not.toContain('203.0.113.7');
  });

  it('separates namespaces', () => {
    expect(buildRateLimitKey('throttle', 'x')).not.toBe(buildRateLimitKey('consume', 'x'));
  });
});

describe('parseRateLimitScriptReply', () => {
  it('coerces the string integers a Lua script may return', () => {
    expect(parseRateLimitScriptReply(['4', '1000', '1', '1000'])).toEqual({
      totalHits: 4,
      timeToExpire: 1000,
      isBlocked: true,
      timeToBlockExpire: 1000,
    });
  });

  it.each([[[]], [[[1, 2, 3]]], [['OK']], [[null]], [[[1, 2, 0]]]])(
    'rejects a malformed reply: %p',
    (reply: unknown) => {
      expect(() => parseRateLimitScriptReply(reply)).toThrow(/unexpected rate-limit script reply/);
    },
  );

  it('rejects negative counters', () => {
    expect(() => parseRateLimitScriptReply([-1, 1000, 0, 0])).toThrow(
      /unexpected rate-limit script reply/,
    );
  });
});

describe('createRateLimitRedisClient', () => {
  it('requires REDIS_URL', () => {
    expect(() => createRateLimitRedisClient({ REDIS_URL: undefined })).toThrow(/REDIS_URL/);
  });
});

describe('REDIS_CLIENT_OPTIONS', () => {
  it('never queues indefinitely and never retries a command', () => {
    expect(REDIS_CLIENT_OPTIONS.lazyConnect).toBe(true);
    expect(REDIS_CLIENT_OPTIONS.maxRetriesPerRequest).toBe(0);
    expect(REDIS_CLIENT_OPTIONS.commandTimeout).toBeGreaterThan(0);
    expect(REDIS_CLIENT_OPTIONS.connectTimeout).toBeGreaterThan(0);
    expect(REDIS_CLIENT_OPTIONS.commandTimeout).toBeLessThanOrEqual(5_000);
  });

  it('caps the reconnect delay instead of using a fixed tight loop', () => {
    const strategy = REDIS_CLIENT_OPTIONS.retryStrategy;

    expect(strategy).toBeDefined();
    expect(strategy?.(1)).toBe(200);
    expect(strategy?.(10_000)).toBe(2_000);
  });
});
