import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { isUuid } from '../src/common/middleware/request-id.middleware';
import { createTestApp } from './helpers/create-test-app';
import { TEST_ENV } from './helpers/test-env';

const ALLOWED_ORIGIN = TEST_ENV.APP_ORIGINS;
const BLOCKED_ORIGIN = 'http://evil.example';
const CLIENT_UUID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

describe('API security baseline (e2e)', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /health', () => {
    it('returns 200 with a minimal body and a request id', async () => {
      const response = await request(app.getHttpServer()).get('/health').expect(200);

      expect(response.body).toEqual({ status: 'ok' });
      expect(isUuid(response.headers['x-request-id'])).toBe(true);
      expect(response.headers['content-type']).toContain('application/json');
      expect(Object.keys(response.body)).toEqual(['status']);
    });
  });

  describe('security headers', () => {
    it('sets helmet defaults and hides the framework', async () => {
      const response = await request(app.getHttpServer()).get('/health').expect(200);

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['content-security-policy']).toContain("default-src 'self'");
      expect(response.headers['strict-transport-security']).toContain('max-age=');
      expect(response.headers['referrer-policy']).toBeDefined();
      expect(response.headers['x-powered-by']).toBeUndefined();
    });
  });

  describe('CORS', () => {
    it('allows an allowlisted origin with credentials', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .set('Origin', ALLOWED_ORIGIN)
        .expect(200);

      expect(response.headers['access-control-allow-origin']).toBe(ALLOWED_ORIGIN);
      expect(response.headers['access-control-allow-credentials']).toBe('true');
      expect(response.headers['access-control-expose-headers']).toContain('x-request-id');
    });

    it('does not allow a non-allowlisted origin', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .set('Origin', BLOCKED_ORIGIN)
        .expect(200);

      // `cors` always emits Allow-Credentials, but without a matching
      // Access-Control-Allow-Origin the browser refuses to expose the response.
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('rejects a preflight from a non-allowlisted origin', async () => {
      const response = await request(app.getHttpServer())
        .options('/health')
        .set('Origin', BLOCKED_ORIGIN)
        .set('Access-Control-Request-Method', 'GET');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('default-deny authentication', () => {
    it('returns 401 for a protected route', async () => {
      const response = await request(app.getHttpServer()).get('/test/protected').expect(401);

      expect(response.body).toEqual({
        statusCode: 401,
        message: 'Unauthorized',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain('stack');
    });

    it('allows a route marked with @Public', async () => {
      await request(app.getHttpServer()).get('/test/echo').expect(200);
    });
  });

  describe('error envelope', () => {
    it('returns a generic 404 with the request id for an unknown route', async () => {
      const response = await request(app.getHttpServer()).get('/does-not-exist').expect(404);

      expect(response.body).toEqual({
        statusCode: 404,
        message: 'Not Found',
        requestId: expect.any(String) as string,
      });
      expect(response.body.requestId).toBe(response.headers['x-request-id']);
      expect(response.text).not.toContain('stack');
      expect(response.text).not.toContain('Cannot GET');
    });

    it('rejects extra body fields (forbidNonWhitelisted)', async () => {
      const response = await request(app.getHttpServer())
        .post('/test/echo')
        .send({ name: 'ok', isAdmin: true })
        .expect(400);

      expect(response.body.message).toBe('Bad Request');
      expect(response.text).not.toContain('isAdmin');
    });

    it('accepts a valid body', async () => {
      const response = await request(app.getHttpServer())
        .post('/test/echo')
        .send({ name: 'ok' })
        .expect(201);

      expect(response.body).toEqual({ name: 'ok' });
    });

    it('rejects an oversized body with a generic 413', async () => {
      const response = await request(app.getHttpServer())
        .post('/test/echo')
        .send({ name: 'x'.repeat(4096) })
        .expect(413);

      expect(response.body).toEqual({
        statusCode: 413,
        message: 'Payload Too Large',
        requestId: expect.any(String) as string,
      });
      expect(response.text).not.toContain('stack');
    });
  });

  describe('request id handling', () => {
    it('echoes a valid client supplied uuid', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .set('x-request-id', CLIENT_UUID)
        .expect(200);

      expect(response.headers['x-request-id']).toBe(CLIENT_UUID);
    });

    it('replaces an invalid client supplied id', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .set('x-request-id', '../../etc/passwd')
        .expect(200);

      expect(response.headers['x-request-id']).not.toBe('../../etc/passwd');
      expect(isUuid(response.headers['x-request-id'])).toBe(true);
    });
  });
});
