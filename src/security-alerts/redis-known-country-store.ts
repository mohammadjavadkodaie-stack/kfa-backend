import { Inject, Injectable } from '@nestjs/common';
import { REDIS_CLIENT, type RateLimitRedisClient } from '../rate-limit/redis-throttler.storage';
import { KNOWN_COUNTRY_STORE, type KnownCountryStore } from './known-country-store';

export const RECORD_KNOWN_COUNTRY_SCRIPT = `
local key = KEYS[1]
local country = ARGV[1]
local ttl = tonumber(ARGV[2])
local cap = tonumber(ARGV[3])

local isNew = redis.call('SISMEMBER', key, country) == 0
local hadAny = redis.call('SCARD', key) > 0
if isNew and redis.call('SCARD', key) < cap then
  redis.call('SADD', key, country)
end
redis.call('EXPIRE', key, ttl)
return { isNew and 1 or 0, hadAny and 1 or 0 }
`;

const KNOWN_COUNTRIES_TTL_SECONDS = 400 * 24 * 60 * 60;
const KNOWN_COUNTRIES_CAP = 20;

interface RedisKnownCountryClient extends RateLimitRedisClient {
  eval(script: string, numberOfKeys: number, ...args: string[]): Promise<unknown>;
}

@Injectable()
export class RedisKnownCountryStore implements KnownCountryStore {
  constructor(@Inject(REDIS_CLIENT) private readonly client: RateLimitRedisClient | null) {}

  async recordAndCheck(
    userId: string,
    country: string,
  ): Promise<{ isNew: boolean; hadAny: boolean }> {
    if (this.client === null) {
      throw new Error('Redis known country store is not configured');
    }

    const result = await (this.client as RedisKnownCountryClient).eval(
      RECORD_KNOWN_COUNTRY_SCRIPT,
      1,
      `known-countries:${userId}`,
      country,
      String(KNOWN_COUNTRIES_TTL_SECONDS),
      String(KNOWN_COUNTRIES_CAP),
    );

    if (!Array.isArray(result) || result.length !== 2) {
      throw new Error('unexpected known country store reply');
    }

    const isNew = Number(result[0]);
    const hadAny = Number(result[1]);
    if (![isNew, hadAny].every((value) => value === 0 || value === 1)) {
      throw new Error('unexpected known country store reply');
    }

    return { isNew: isNew === 1, hadAny: hadAny === 1 };
  }
}

export { KNOWN_COUNTRY_STORE };
