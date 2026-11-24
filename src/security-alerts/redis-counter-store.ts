import { Inject, Injectable } from '@nestjs/common';
import {
  REDIS_CLIENT,
  buildRateLimitKey,
  type RateLimitRedisClient,
} from '../rate-limit/redis-throttler.storage';
import { COUNTER_STORE, type CounterStore } from './counter-store';

export const INCREMENT_SECURITY_ALERT_COUNTER_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
`;

interface RedisCounterClient extends RateLimitRedisClient {
  eval(script: string, numberOfKeys: number, ...args: string[]): Promise<unknown>;
}

@Injectable()
export class RedisCounterStore implements CounterStore {
  constructor(@Inject(REDIS_CLIENT) private readonly client: RateLimitRedisClient | null) {}

  async incr(key: string, windowSeconds: number): Promise<number> {
    if (!Number.isInteger(windowSeconds) || windowSeconds <= 0) {
      throw new Error('windowSeconds must be a positive integer');
    }

    if (this.client === null) {
      throw new Error('Redis counter store is not configured');
    }

    const redisKey = buildRateLimitKey('security-alert', key);
    const result = await (this.client as RedisCounterClient).eval(
      INCREMENT_SECURITY_ALERT_COUNTER_SCRIPT,
      1,
      redisKey,
      String(windowSeconds),
    );
    const count = typeof result === 'number' ? result : Number(result);

    if (!Number.isSafeInteger(count) || count < 1) {
      throw new Error('unexpected security alert counter reply');
    }

    return count;
  }
}

export { COUNTER_STORE };
