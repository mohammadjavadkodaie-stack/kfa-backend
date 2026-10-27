import { Redis } from 'ioredis';
import type { Env } from '../src/config/env';
import { RateLimitService } from '../src/rate-limit/rate-limit.service';
import {
  createRateLimitRedisClient,
  RATE_LIMIT_KEY_PREFIX,
  REDIS_CLIENT_OPTIONS,
  RedisThrottlerStorage,
  type RateLimitRecord,
  type RateLimitRedisClient,
} from '../src/rate-limit/redis-throttler.storage';

/**
 * Real-Redis suite. Skipped unless `REDIS_URL_TEST` points at a throwaway Redis
 * (for example the `redis` service in docker-compose.dev.yml):
 *
 *   REDIS_URL_TEST=redis://:dev-only-change-me@127.0.0.1:6380/0 pnpm test:e2e
 *
 * Point it at a THROWAWAY instance only: the suite flushes `kfa:rl:*` keys.
 */
const REDIS_URL = process.env.REDIS_URL_TEST;
const HMAC_KEY = 'test-only-rate-limit-hmac-key-0123456789';
const SCOPE = `redis-e2e-${Date.now().toString(36)}`;
const IDENTIFIER = '+15550001111';
const LIMIT = 3;
const WINDOW_SECONDS = 60;

const describeWithRedis = REDIS_URL === undefined ? describe.skip : describe;

describeWithRedis('Redis rate limiting (e2e)', () => {
  let admin: Redis;
  let client: RateLimitRedisClient;
  let otherClient: RateLimitRedisClient;
  let storage: RedisThrottlerStorage;
  let service: RateLimitService;
  let otherService: RateLimitService;

  beforeAll(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    admin = new Redis(REDIS_URL, REDIS_CLIENT_OPTIONS);
    // Fail fast (and skip-safely) when the URL points at nothing.
    await admin.ping();

    client = createRateLimitRedisClient({ REDIS_URL });
    otherClient = createRateLimitRedisClient({ REDIS_URL });

    storage = new RedisThrottlerStorage(client, { RATE_LIMIT_HMAC_KEY: HMAC_KEY } as Env);
    service = new RateLimitService(client, { RATE_LIMIT_HMAC_KEY: HMAC_KEY } as Env);
    // A second client simulates a second API instance sharing the same store.
    otherService = new RateLimitService(otherClient, { RATE_LIMIT_HMAC_KEY: HMAC_KEY } as Env);
  });

  afterEach(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    const keys = await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`);

    if (keys.length > 0) {
      await admin.del(...keys);
    }
  });

  afterAll(async () => {
    if (REDIS_URL === undefined) {
      return;
    }

    await storage.onModuleDestroy();
    await otherClient.quit().catch(() => undefined);
    await admin.quit();
  });

  it('allows the limit and blocks afterwards, atomically', async () => {
    const input = {
      scope: SCOPE,
      identifier: IDENTIFIER,
      limit: LIMIT,
      windowSeconds: WINDOW_SECONDS,
    };

    await expect(service.consume(input)).resolves.toEqual({
      allowed: true,
      remaining: LIMIT - 1,
      retryAfterSeconds: 0,
    });
    await expect(service.consume(input)).resolves.toEqual({
      allowed: true,
      remaining: LIMIT - 2,
      retryAfterSeconds: 0,
    });
    await expect(service.consume(input)).resolves.toEqual({
      allowed: true,
      remaining: 0,
      retryAfterSeconds: 0,
    });

    const blocked = await service.consume(input);

    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
    expect(blocked.retryAfterSeconds).toBeLessThanOrEqual(WINDOW_SECONDS);
  });

  it('shares counters between instances', async () => {
    const input = {
      scope: `${SCOPE}-shared`,
      identifier: IDENTIFIER,
      limit: LIMIT,
      windowSeconds: WINDOW_SECONDS,
    };

    for (let hit = 0; hit < LIMIT; hit += 1) {
      await expect(service.consume(input)).resolves.toMatchObject({ allowed: true });
    }

    await expect(otherService.consume(input)).resolves.toMatchObject({ allowed: false });
  });

  it('never writes the raw identifier into a key', async () => {
    await service.consume({
      scope: `${SCOPE}-keys`,
      identifier: IDENTIFIER,
      limit: LIMIT,
      windowSeconds: WINDOW_SECONDS,
    });

    const keys = await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`);

    expect(keys.length).toBeGreaterThan(0);

    for (const key of keys) {
      expect(key.startsWith(RATE_LIMIT_KEY_PREFIX)).toBe(true);
      expect(key).not.toContain('15550001111');
      expect(key).toMatch(/:[0-9a-f]{64}$/);
    }
  });

  it('expires counters so the window resets on its own', async () => {
    const input = {
      scope: `${SCOPE}-ttl`,
      identifier: IDENTIFIER,
      limit: LIMIT,
      windowSeconds: WINDOW_SECONDS,
    };

    await service.consume(input);

    const [key] = await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`);
    const ttl = await admin.pttl(key as string);

    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(WINDOW_SECONDS * 1_000);
  });

  it('exposes the throttler storage against the same atomic script', async () => {
    const record = await storage.increment(
      '203.0.113.7',
      WINDOW_SECONDS * 1_000,
      LIMIT,
      0,
      'default',
    );

    expect(record).toMatchObject({ totalHits: 1, isBlocked: false });
    expect(record.timeToExpire).toBeGreaterThan(0);
    // Seconds, not ms: the guard turns this straight into Retry-After.
    expect(record.timeToExpire).toBe(WINDOW_SECONDS);
  });

  it('does not extend the block while a client keeps retrying', async () => {
    const tracker = '203.0.113.11';
    const windowMs = 2_000;
    const blockMs = 5_000;
    const limit = 2;

    await storage.increment(tracker, windowMs, limit, blockMs, 'default');
    await expect(
      storage.increment(tracker, windowMs, limit, blockMs, 'default'),
    ).resolves.toMatchObject({ totalHits: 2, isBlocked: false });

    const blocked: RateLimitRecord[] = [];
    const pttls: number[] = [];
    let redisKey = '';

    for (let hit = 3; hit <= 5; hit += 1) {
      if (hit > 3) {
        // Space the retries out so an extended TTL would show up in PTTL.
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      blocked.push(await storage.increment(tracker, windowMs, limit, blockMs, 'default'));

      if (hit === 3) {
        const [key] = await admin.keys(`${RATE_LIMIT_KEY_PREFIX}*`);
        redisKey = key as string;
      }

      pttls.push(await admin.pttl(redisKey));
    }

    let previousTimeToBlockExpire = Number.POSITIVE_INFINITY;

    for (const record of blocked) {
      expect(record.isBlocked).toBe(true);
      expect(record.timeToBlockExpire).toBeGreaterThan(0);
      expect(record.timeToBlockExpire).toBeLessThanOrEqual(Math.ceil(blockMs / 1_000));
      // Retrying must never push the release time out.
      expect(record.timeToBlockExpire).toBeLessThanOrEqual(previousTimeToBlockExpire);
      previousTimeToBlockExpire = record.timeToBlockExpire;
    }

    const firstHitPttl = pttls[0] as number;
    const lastHitPttl = pttls[pttls.length - 1] as number;

    // The first blocked hit replaced the window TTL with the block duration...
    expect(firstHitPttl).toBeGreaterThan(windowMs);
    expect(firstHitPttl).toBeLessThanOrEqual(blockMs);
    // ...and the later ones only let it run down.
    expect(lastHitPttl).toBeGreaterThan(0);
    expect(lastHitPttl).toBeLessThan(firstHitPttl);

    // The block must actually end, no matter how often the client retried.
    await new Promise((resolve) => setTimeout(resolve, blockMs + 250));

    await expect(
      storage.increment(tracker, windowMs, limit, blockMs, 'default'),
    ).resolves.toMatchObject({ totalHits: 1, isBlocked: false });
  });
});
