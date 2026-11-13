import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import type { RateLimitService } from '../src/rate-limit/rate-limit.service';
import { FakeRateLimit } from './helpers/auth-service-harness';
import { createTestApp } from './helpers/create-test-app';
import { EMAIL_TEST_CODE, createEmailHarness, type EmailHarness } from './helpers/email-harness';

/**
 * The dev frontend sends `fake-captcha-token`. Outside production the fake
 * verifier must accept it, so `POST /auth/email/start` reaches the code step
 * instead of answering the generic 400. This suite boots the real application
 * with `NODE_ENV=development`, one in-memory code store and session repository,
 * the fake transport and an always-allowing limiter; nothing else is replaced.
 */
describe('Dev captcha token over HTTP (e2e)', () => {
  let app: NestExpressApplication;
  let email: EmailHarness;

  beforeAll(async () => {
    email = createEmailHarness();
    app = await createTestApp(
      { NODE_ENV: 'development' },
      {
        sessionRepository: new InMemorySessionRepository(),
        rateLimit: new FakeRateLimit() as unknown as RateLimitService,
        emailCodeStore: email.store,
        emailProvider: email.provider,
      },
    );
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns 202 for POST /auth/email/start with the dev captcha token', async () => {
    const address = 'dev-captcha@example.com';

    const response = await request(app.getHttpServer())
      .post('/auth/email/start')
      .send({ email: address, purpose: 'register', captchaToken: 'fake-captcha-token' });

    expect(response.status).toBe(202);
    expect(email.provider.lastCode(address, 'register')).toBe(EMAIL_TEST_CODE);
  });

  it('keeps the generic 400 body for a wrong captcha token', async () => {
    const address = 'dev-captcha-wrong@example.com';

    const response = await request(app.getHttpServer())
      .post('/auth/email/start')
      .send({ email: address, purpose: 'register', captchaToken: 'fake-captcha-token-wrong' });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      statusCode: 400,
      message: 'Bad Request',
      requestId: expect.any(String) as string,
    });
    expect(email.provider.lastCode(address, 'register')).toBeNull();
  });
});
