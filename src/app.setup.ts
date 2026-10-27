import { ValidationPipe } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { Logger } from 'nestjs-pino';
import type { Env } from './config/env';
import { REQUEST_ID_HEADER, requestIdMiddleware } from './common/middleware/request-id.middleware';
import { createBodyParserErrorHandler } from './common/middleware/body-parser-error.middleware';

/** Explicit CORS allowlists - no wildcards, no reflection of arbitrary origins. */
export const CORS_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export const CORS_ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'X-Request-Id'] as const;
export const CORS_MAX_AGE_SECONDS = 600;

/**
 * HTTP hardening shared by `main.ts` and the tests.
 *
 * Middleware order is intentional:
 * request id -> helmet -> CORS -> body parsers -> body-parser error mapper.
 */
export function configureApp(app: NestExpressApplication, env: Env): void {
  app.disable('x-powered-by');
  app.set('trust proxy', env.TRUSTED_PROXY_COUNT > 0 ? env.TRUSTED_PROXY_COUNT : false);

  app.use(requestIdMiddleware);
  app.use(helmet());
  app.enableCors({
    origin: [...env.APP_ORIGINS],
    credentials: true,
    methods: [...CORS_ALLOWED_METHODS],
    allowedHeaders: [...CORS_ALLOWED_HEADERS],
    exposedHeaders: [REQUEST_ID_HEADER],
    maxAge: CORS_MAX_AGE_SECONDS,
    optionsSuccessStatus: 204,
  });

  app.useBodyParser('json', { limit: env.BODY_LIMIT_BYTES });
  app.useBodyParser('urlencoded', { extended: false, limit: env.BODY_LIMIT_BYTES });
  app.use(createBodyParserErrorHandler(app.get(Logger)));

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
}
