import { ValidationPipe } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { Logger } from 'nestjs-pino';
import type { Env } from './config/env';
import { REQUEST_ID_HEADER, requestIdMiddleware } from './common/middleware/request-id.middleware';
import { createBodyParserErrorHandler } from './common/middleware/body-parser-error.middleware';
import { createRawBodyMiddleware } from './common/middleware/raw-body.middleware';
import {
  DOCUMENT_UPLOAD_MEDIA_TYPES,
  DOCUMENT_UPLOAD_PATH,
} from './documents/document-upload.controller';
import { MAX_UPLOAD_BYTES } from './documents/ingest/ingest.constants';

/** Explicit CORS allowlists - no wildcards, no reflection of arbitrary origins. */
export const CORS_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export const CORS_ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Request-Id',
  // Device fingerprint used by the OTP endpoints; without it browsers fail
  // preflight and the device-scoped throttles never engage.
  'X-Device-Key',
] as const;
export const CORS_MAX_AGE_SECONDS = 600;

/**
 * HTTP hardening shared by `main.ts` and the tests.
 *
 * Middleware order is intentional:
 * request id -> helmet -> CORS -> body parsers (JSON, urlencoded, and the raw
 * parser bound to the document upload route) -> body-parser error mapper.
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

  // The document upload route takes the file as the body, so it gets its own raw
  // parser bound to that one path. The JSON limit above stays as small as it is
  // for every other route, and an oversized upload is refused by the parser
  // itself (generic 413) before it is buffered, not after. A media type outside
  // the list is not read at all - the handler turns that into a 415.
  app.use(
    DOCUMENT_UPLOAD_PATH,
    createRawBodyMiddleware({
      mediaTypes: DOCUMENT_UPLOAD_MEDIA_TYPES,
      limitBytes: MAX_UPLOAD_BYTES,
    }),
  );

  app.use(createBodyParserErrorHandler(app.get(Logger)));

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
}
