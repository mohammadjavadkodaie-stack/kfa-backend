import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { createHash, createHmac } from 'node:crypto';
import type { Env } from '../config/env';
import { RateLimitService, type ConsumeRateLimitInput } from './rate-limit.service';
import { RATE_LIMIT_KEY_PREFIX, type RateLimitRedisClient } from './redis-throttler.storage';

const HMAC_KEY = 'unit-test-rate-limit-hmac-key-0123456789';
const RAW_PHONE = '+15551234567';
const LIMIT = 3;
const WINDOW_SECONDS = 60;

const INPUT: ConsumeRateLimitInput = {
  scope: 'otp-send',
  identifier: RAW_PHONE,
  limit: LIMIT,
  windowSeconds: WINDOW_SECONDS,
};

function env(overrides: Partial<Env> = {}): Env {
  return { RATE_LIMIT_HMAC_KEY: HMAC_KEY, ...overrides } as Env;
}

function createHarness(overrides: Partial<Env> = {}) {
  const client = {
    status: 'ready',
    incrementRateLimitWindow: jest.fn(),
    quit: jest.fn().mockResolvedValue('OK'),
    disconnect: jest.fn(),
  };

  const service = new RateLimitService(client as unknown as RateLimitRedisClient, env(overrides));

  return { service, client };
}

function expectedKey(input: ConsumeRateLimitInput = INPUT): string {
  const hmac = createHmac('sha256', HMAC_KEY).update(RAW_PHONE, 'utf8').digest('hex');
  const digest = createHash('sha256')
    .update(`consume:${input.scope}:${hmac}`, 'utf8')
    .digest('hex');

  return `${RATE_LIMIT_KEY_PREFIX}consume:${digest}`;
}

describe('RateLimitService.consume', () => {
  it('keys on an HMAC of the identifier and never on the raw value', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([1, 60_000, 0, 0]);

    await service.consume(INPUT);

    const [key, limit, windowMs, blockMs] = client.incrementRateLimitWindow.mock.calls[0] as [
      string,
      number,
      number,
      number,
    ];

    expect(key).toBe(expectedKey());
    expect(key).not.toContain(RAW_PHONE);
    expect(key).not.toContain('15551234567');
    expect({ limit, windowMs, blockMs }).toEqual({
      limit: LIMIT,
      windowMs: WINDOW_SECONDS * 1_000,
      blockMs: 0,
    });
  });

  it('allows a request below the limit and reports the remaining budget', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([1, 60_000, 0, 0]);

    await expect(service.consume(INPUT)).resolves.toEqual({
      allowed: true,
      remaining: LIMIT - 1,
      retryAfterSeconds: 0,
    });
  });

  it('never reports a negative remaining budget once blocked', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([9, 60_000, 1, 60_000]);

    await expect(service.consume(INPUT)).resolves.toEqual({
      allowed: false,
      remaining: 0,
      retryAfterSeconds: 60,
    });
  });

  it('rounds the retry delay up to whole seconds', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([4, 60_000, 1, 1_500]);

    await expect(service.consume(INPUT)).resolves.toMatchObject({
      allowed: false,
      retryAfterSeconds: 2,
    });
  });

  it('fails closed without a Redis client', async () => {
    const service = new RateLimitService(null, env());

    await expect(service.consume(INPUT)).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('fails closed without a rate-limit HMAC key', async () => {
    const { service } = createHarness({ RATE_LIMIT_HMAC_KEY: undefined });

    await expect(service.consume(INPUT)).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('fails closed with a generic error when Redis is unreachable', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockRejectedValue(
      new Error(`ECONNREFUSED redis://default:${HMAC_KEY}@10.0.0.5:6379 key=${expectedKey()}`),
    );

    const error = await service.consume(INPUT).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expect((error as Error).message).toBe('Service Unavailable');
    expect((error as Error).message).not.toContain('10.0.0.5');
    expect((error as Error).message).not.toContain(RAW_PHONE);
  });

  it('fails closed when the stored reply is malformed', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([1, 0, 0]);

    await expect(service.consume(INPUT)).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it.each([
    { ...INPUT, scope: '' },
    { ...INPUT, identifier: '' },
    { ...INPUT, limit: 0 },
    { ...INPUT, windowSeconds: 0 },
    { ...INPUT, limit: 1.5 },
  ])('rejects invalid input before touching Redis: %p', async (invalid) => {
    const { service, client } = createHarness();

    await expect(service.consume(invalid)).rejects.toBeInstanceOf(BadRequestException);
    expect(client.incrementRateLimitWindow).not.toHaveBeenCalled();
  });

  it('derives a different key per scope', async () => {
    const { service, client } = createHarness();

    client.incrementRateLimitWindow.mockResolvedValue([1, 60_000, 0, 0]);

    await service.consume(INPUT);
    await service.consume({ ...INPUT, scope: 'login' });

    const keys = client.incrementRateLimitWindow.mock.calls.map((call) => call[0] as string);

    expect(keys[0]).not.toBe(keys[1]);
  });
});
