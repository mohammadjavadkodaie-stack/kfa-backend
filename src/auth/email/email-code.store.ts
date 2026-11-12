export type EmailCodeVerifyResult = 'ok' | 'wrong' | 'locked_now' | 'locked' | 'missing';

export interface EmailCodeStore {
  put(key: string, hash: string, ttlSeconds: number): Promise<void>;
  verifyAndConsume(
    key: string,
    candidateHash: string,
    maxAttempts: number,
  ): Promise<EmailCodeVerifyResult>;
}

export class EmailCodeStoreUnavailableError extends Error {
  constructor() {
    super('email code store unavailable');
    this.name = 'EmailCodeStoreUnavailableError';
  }
}

export interface EmailCodeRedisClient {
  eval(script: string, numberOfKeys: number, key: string, ...args: string[]): Promise<unknown>;
}

export const PUT_EMAIL_CODE_SCRIPT = `
redis.call('HSET', KEYS[1], 'h', ARGV[1], 'a', '0')
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 'ok'
`;

export const VERIFY_EMAIL_CODE_SCRIPT = `
local hash = redis.call('HGET', KEYS[1], 'h')
if not hash then return 'missing' end

local attempts = tonumber(redis.call('HGET', KEYS[1], 'a')) or 0
local maxAttempts = tonumber(ARGV[2])
if attempts >= maxAttempts then return 'locked' end

attempts = redis.call('HINCRBY', KEYS[1], 'a', 1)
if hash == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 'ok'
end
if attempts >= maxAttempts then return 'locked_now' end
return 'wrong'
`;

function assertScriptReply(reply: unknown): EmailCodeVerifyResult {
  if (
    reply === 'ok' ||
    reply === 'wrong' ||
    reply === 'locked_now' ||
    reply === 'locked' ||
    reply === 'missing'
  ) {
    return reply;
  }

  throw new EmailCodeStoreUnavailableError();
}

export class RedisEmailCodeStore implements EmailCodeStore {
  constructor(private readonly client: EmailCodeRedisClient) {}

  async put(key: string, hash: string, ttlSeconds: number): Promise<void> {
    try {
      const reply = await this.client.eval(PUT_EMAIL_CODE_SCRIPT, 1, key, hash, String(ttlSeconds));
      if (reply !== 'ok') throw new EmailCodeStoreUnavailableError();
    } catch (error) {
      if (error instanceof EmailCodeStoreUnavailableError) throw error;
      throw new EmailCodeStoreUnavailableError();
    }
  }

  async verifyAndConsume(
    key: string,
    candidateHash: string,
    maxAttempts: number,
  ): Promise<EmailCodeVerifyResult> {
    try {
      return assertScriptReply(
        await this.client.eval(
          VERIFY_EMAIL_CODE_SCRIPT,
          1,
          key,
          candidateHash,
          String(maxAttempts),
        ),
      );
    } catch (error) {
      if (error instanceof EmailCodeStoreUnavailableError) throw error;
      throw new EmailCodeStoreUnavailableError();
    }
  }
}

interface Entry {
  readonly hash: string;
  attempts: number;
  readonly expiresAt: number;
}

export type EmailCodeClock = () => number;

export class InMemoryEmailCodeStore implements EmailCodeStore {
  private readonly entries = new Map<string, Entry>();

  constructor(private readonly clock: EmailCodeClock = Date.now) {}

  async put(key: string, hash: string, ttlSeconds: number): Promise<void> {
    this.entries.set(key, {
      hash,
      attempts: 0,
      expiresAt: this.clock() + ttlSeconds * 1_000,
    });
  }

  async verifyAndConsume(
    key: string,
    candidateHash: string,
    maxAttempts: number,
  ): Promise<EmailCodeVerifyResult> {
    const entry = this.entries.get(key);
    if (entry === undefined || entry.expiresAt <= this.clock()) {
      this.entries.delete(key);
      return 'missing';
    }
    if (entry.attempts >= maxAttempts) return 'locked';

    entry.attempts += 1;
    if (entry.hash === candidateHash) {
      this.entries.delete(key);
      return 'ok';
    }
    if (entry.attempts >= maxAttempts) return 'locked_now';
    return 'wrong';
  }
}
