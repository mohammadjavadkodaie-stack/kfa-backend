import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { Response } from 'express';
import type { RawBodyRequest } from '../common/middleware/raw-body.middleware';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../rate-limit/rate-limit.service';
import {
  BILLING_WEBHOOK_PATH,
  BILLING_WEBHOOK_RATE_LIMITS,
  BILLING_WEBHOOK_RATE_LIMIT_SCOPE,
  BillingWebhookController,
} from './billing-webhook.controller';
import type { BillingWebhookService, WebhookOutcome } from './billing-webhook.service';
import type { WebhookHeaders } from './webhook-verifier';

const REQUEST_ID = 'request-1';
const ADDRESS = '203.0.113.7';
const PAYLOAD = Buffer.from('{"payment_id":"p-1"}', 'utf8');

class FakeRateLimit {
  readonly calls: ConsumeRateLimitInput[] = [];
  allowed = true;

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    this.calls.push(input);

    return { allowed: this.allowed, remaining: 0, retryAfterSeconds: 7 };
  }
}

class FakeWebhooks {
  readonly calls: { provider: string; rawBody: Buffer; headers: WebhookHeaders }[] = [];
  outcome: WebhookOutcome = { accepted: true, knownProvider: true, retryLater: false };

  async handle(
    provider: string,
    rawBody: Buffer,
    headers: WebhookHeaders,
  ): Promise<WebhookOutcome> {
    this.calls.push({ provider, rawBody, headers });

    return this.outcome;
  }
}

interface FakeResponse {
  readonly status: jest.Mock;
  readonly setHeader: jest.Mock;
}

function response(): FakeResponse {
  return { status: jest.fn(), setHeader: jest.fn() };
}

function request(options: { body?: Buffer | undefined; ip?: string } = {}): RawBodyRequest {
  return {
    id: REQUEST_ID,
    ip: options.ip ?? ADDRESS,
    // `body: undefined` has to mean "no body", not "use the default payload".
    rawBody: 'body' in options ? options.body : PAYLOAD,
    headers: { 'x-signature': 'sig' },
  } as unknown as RawBodyRequest;
}

function controller(webhooks = new FakeWebhooks(), rateLimit = new FakeRateLimit()) {
  return {
    webhooks,
    rateLimit,
    controller: new BillingWebhookController(
      webhooks as unknown as BillingWebhookService,
      rateLimit as unknown as RateLimitService,
    ),
  };
}

describe('BillingWebhookController', () => {
  it('is mounted under the path the raw body parser is bound to', () => {
    expect(BILLING_WEBHOOK_PATH).toBe('billing/webhook');
  });

  it('answers 429 once the address is over budget', async () => {
    const rateLimit = new FakeRateLimit();
    rateLimit.allowed = false;
    const res = response();
    const { controller: subject, webhooks } = controller(new FakeWebhooks(), rateLimit);

    const result = await subject.receive('nowpayments', request(), res as unknown as Response);

    expect(result).toEqual({
      statusCode: 429,
      message: 'Too Many Requests',
      requestId: REQUEST_ID,
    });
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '7');
    expect(webhooks.calls).toHaveLength(0);
  });

  it('stops at the first refused window', async () => {
    const rateLimit = new FakeRateLimit();
    rateLimit.allowed = false;
    const { controller: subject } = controller(new FakeWebhooks(), rateLimit);

    await subject.receive('nowpayments', request(), response() as unknown as Response);

    expect(rateLimit.calls).toHaveLength(1);
  });

  it('counts the request against the client address in its own bucket', async () => {
    const rateLimit = new FakeRateLimit();
    const { controller: subject } = controller(new FakeWebhooks(), rateLimit);

    await subject.receive('nowpayments', request(), response() as unknown as Response);

    expect(rateLimit.calls).toEqual(
      BILLING_WEBHOOK_RATE_LIMITS.map((limit) => ({
        scope: BILLING_WEBHOOK_RATE_LIMIT_SCOPE,
        identifier: ADDRESS,
        ...limit,
      })),
    );
  });

  it('answers 404 for a provider name that cannot name a provider', async () => {
    const { controller: subject, webhooks } = controller();

    await expect(
      subject.receive('not a provider', request(), response() as unknown as Response),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(webhooks.calls).toHaveLength(0);
  });

  it('answers 404 when no verifier is configured for the provider', async () => {
    const webhooks = new FakeWebhooks();
    webhooks.outcome = { accepted: false, knownProvider: false, retryLater: false };
    const { controller: subject } = controller(webhooks);

    await expect(
      subject.receive('nowpayments', request(), response() as unknown as Response),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('answers 400 when the parser kept no JSON body', async () => {
    const { controller: subject, webhooks } = controller();

    await expect(
      subject.receive(
        'nowpayments',
        request({ body: undefined }),
        response() as unknown as Response,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(webhooks.calls).toHaveLength(0);
  });

  it('passes the uppercased provider, the exact bytes and the headers on', async () => {
    const { controller: subject, webhooks } = controller();

    const result = await subject.receive(
      'nowpayments',
      request(),
      response() as unknown as Response,
    );

    expect(result).toEqual({ accepted: true });
    expect(webhooks.calls).toEqual([
      { provider: 'NOWPAYMENTS', rawBody: PAYLOAD, headers: { 'x-signature': 'sig' } },
    ]);
  });

  it('reports a forged signature as handled, so the provider stops resending it', async () => {
    const webhooks = new FakeWebhooks();
    webhooks.outcome = { accepted: false, knownProvider: true, retryLater: false };
    const { controller: subject } = controller(webhooks);

    await expect(
      subject.receive('nowpayments', request(), response() as unknown as Response),
    ).resolves.toEqual({ accepted: false });
  });
});
