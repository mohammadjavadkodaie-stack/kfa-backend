import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { createTestApp } from './helpers/create-test-app';

/**
 * OTP endpoints without a Redis store.
 *
 * The whole flow is fail-closed: the in-memory throttler still lets the request
 * through, but every limit and every proof nonce lives in Redis, so the API must
 * answer 503 instead of silently dropping the protections. Only requests that
 * are rejected before the limiter (malformed bodies) can be answered without it.
 */
const PHONE = '+14155552671';
const START_BODY = { phone: PHONE, purpose: 'login', captchaToken: 'fake-captcha-pass' };
const VERIFY_BODY = { phone: PHONE, purpose: 'login', code: '123456' };

describe('OTP endpoints without Redis (e2e)', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /auth/otp/start', () => {
    it('fails closed with a generic 503 for a well-formed request', async () => {
      const response = await request(app.getHttpServer()).post('/auth/otp/start').send(START_BODY);

      expect(response.status).toBe(503);
      expect(response.body).toEqual({
        statusCode: 503,
        message: 'Service Unavailable',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain(PHONE);
      expect(response.text).not.toContain('redis');
      expect(response.text).not.toContain('stack');
    });

    it.each([
      ['a non-object body', [{ phone: PHONE }]],
      ['a missing captcha token', [{ phone: PHONE, purpose: 'login' }]],
      ['a missing purpose', [{ phone: PHONE, captchaToken: 'fake-captcha-pass' }]],
      ['an unknown purpose', [{ ...START_BODY, purpose: 'admin' }]],
      ['an extra field', [{ ...START_BODY, isAdmin: true }]],
      [
        'an oversized phone',
        [{ phone: `+${'9'.repeat(21)}`, purpose: 'login', captchaToken: 'x' }],
      ],
      ['a non-string captcha token', [{ phone: PHONE, purpose: 'login', captchaToken: 42 }]],
    ])('rejects %s with a generic envelope', async (_label, [body]) => {
      const response = await request(app.getHttpServer()).post('/auth/otp/start').send(body);

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        statusCode: 400,
        message: 'Bad Request',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain('stack');
    });
  });

  describe('POST /auth/otp/verify', () => {
    it('rejects a malformed body as an invalid code before touching Redis', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/otp/verify')
        .send({ phone: PHONE, purpose: 'login', code: '12345' });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: 'invalid_code' });
    });

    it.each(['', 'admin', 'phone_change'])(
      'rejects the %p purpose as an invalid code before touching Redis',
      async (purpose) => {
        const response = await request(app.getHttpServer())
          .post('/auth/otp/verify')
          .send({ phone: PHONE, purpose, code: '123456' });

        expect(response.status).toBe(400);
        expect(response.body).toEqual({ error: 'invalid_code' });
      },
    );

    it('rejects an unparseable phone before touching Redis when the schema fails', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/otp/verify')
        .send({ phone: 'not-a-phone', purpose: 'login', code: '1234567' });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: 'invalid_code' });
    });

    it('fails closed with a generic 503 for a well-formed request', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/otp/verify')
        .send(VERIFY_BODY);

      expect(response.status).toBe(503);
      expect(response.body).toEqual({
        statusCode: 503,
        message: 'Service Unavailable',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain(PHONE);
      expect(response.text).not.toContain('stack');
    });
  });

  it('never answers 401: both endpoints are public', async () => {
    await request(app.getHttpServer()).post('/auth/otp/start').send(START_BODY).expect(503);
    await request(app.getHttpServer()).post('/auth/otp/verify').send(VERIFY_BODY).expect(503);
  });
});
