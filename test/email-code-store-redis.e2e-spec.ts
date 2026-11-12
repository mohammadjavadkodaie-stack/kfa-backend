import { Redis } from 'ioredis';
import { RedisEmailCodeStore, type EmailCodeStore } from '../src/auth/email/email-code.store';
import { REDIS_CLIENT_OPTIONS } from '../src/rate-limit/redis-throttler.storage';

const REDIS_URL = process.env.REDIS_URL_TEST;
const describeWithRedis = REDIS_URL === undefined ? describe.skip : describe;

describeWithRedis('RedisEmailCodeStore (e2e)', () => {
  let admin: Redis;
  let store: EmailCodeStore;
  let sequence = 0;

  beforeAll(async () => {
    if (REDIS_URL === undefined) return;
    admin = new Redis(REDIS_URL, REDIS_CLIENT_OPTIONS);
    await admin.ping();
    store = new RedisEmailCodeStore(admin);
  });

  afterAll(async () => {
    if (REDIS_URL !== undefined) await admin.quit();
  });

  beforeEach(async () => {
    if (REDIS_URL === undefined) return;
    await admin.flushdb();
  });

  function key(): string {
    sequence += 1;
    return `kfa:ecode:test:${sequence}`;
  }

  it('consumes a correct code only once', async () => {
    const redisKey = key();
    await store.put(redisKey, 'hash', 60);

    await expect(store.verifyAndConsume(redisKey, 'hash', 3)).resolves.toBe('ok');
    await expect(store.verifyAndConsume(redisKey, 'hash', 3)).resolves.toBe('missing');
  });

  it('increments attempts on wrong codes', async () => {
    const redisKey = key();
    await store.put(redisKey, 'hash', 60);

    await expect(store.verifyAndConsume(redisKey, 'wrong', 3)).resolves.toBe('wrong');
    await expect(store.verifyAndConsume(redisKey, 'wrong', 3)).resolves.toBe('wrong');
  });

  it('returns locked_now on the maximum wrong attempt and then locked', async () => {
    const redisKey = key();
    await store.put(redisKey, 'hash', 60);

    await expect(store.verifyAndConsume(redisKey, 'wrong', 2)).resolves.toBe('wrong');
    await expect(store.verifyAndConsume(redisKey, 'wrong', 2)).resolves.toBe('locked_now');
    await expect(store.verifyAndConsume(redisKey, 'hash', 2)).resolves.toBe('locked');
  });

  it('returns missing after expiry', async () => {
    const redisKey = key();
    await store.put(redisKey, 'hash', 1);
    await new Promise((resolve) => setTimeout(resolve, 1_100));

    await expect(store.verifyAndConsume(redisKey, 'hash', 3)).resolves.toBe('missing');
  });

  it('resets attempts when replacing a code', async () => {
    const redisKey = key();
    await store.put(redisKey, 'first', 60);
    await store.verifyAndConsume(redisKey, 'wrong', 2);
    await store.put(redisKey, 'second', 60);

    await expect(store.verifyAndConsume(redisKey, 'second', 2)).resolves.toBe('ok');
  });

  it('keeps separate keys independent', async () => {
    const one = key();
    const two = key();
    await store.put(one, 'one-hash', 60);
    await store.put(two, 'two-hash', 60);

    await expect(store.verifyAndConsume(one, 'wrong', 1)).resolves.toBe('locked_now');
    await expect(store.verifyAndConsume(two, 'two-hash', 1)).resolves.toBe('ok');
  });

  it('does not exceed the attempt limit under concurrent verification', async () => {
    const redisKey = key();
    const maxAttempts = 5;
    await store.put(redisKey, 'hash', 60);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => store.verifyAndConsume(redisKey, 'wrong', maxAttempts)),
    );

    expect(results.filter((result) => result === 'wrong' || result === 'locked_now')).toHaveLength(
      maxAttempts,
    );
    expect(results.filter((result) => result === 'locked')).toHaveLength(20 - maxAttempts);
  });
});
