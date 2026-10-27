import type { NextFunction, Request, Response } from 'express';
import { toErrorResponseBody } from '../errors/error-response';
import { getRequestId } from './request-id.middleware';

/**
 * Body-parser failures (oversized payload, malformed JSON, ...) are raised by
 * middleware that runs before Nest routing, so they never reach the Nest
 * exception filter. This Express error handler converts them into the same
 * generic JSON envelope, and logs the real cause server-side only.
 */

/**
 * Minimal logging contract for middleware that cannot rely on dependency
 * injection. `nestjs-pino`'s `Logger` (a singleton adapter) satisfies it and
 * still resolves the per-request logger from the request context.
 */
export interface RequestLogger {
  warn(payload: Record<string, unknown>): void;
}

const STATUS_BY_TYPE: Readonly<Record<string, number>> = Object.freeze({
  'entity.too.large': 413,
  'entity.parse.failed': 400,
  'entity.verify.failed': 403,
  'request.aborted': 400,
  'request.size.invalid': 400,
  'parameters.too.many': 413,
  'charset.unsupported': 415,
  'encoding.unsupported': 415,
});

function readErrorType(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }

  const type = (error as { type?: unknown }).type;
  return typeof type === 'string' ? type : undefined;
}

/** Returns the generic HTTP status for a known body-parser error, if any. */
export function resolveBodyParserStatus(error: unknown): number | undefined {
  const type = readErrorType(error);
  return type === undefined ? undefined : STATUS_BY_TYPE[type];
}

type BodyParserErrorHandler = (
  error: unknown,
  request: Request,
  response: Response,
  next: NextFunction,
) => void;

export function createBodyParserErrorHandler(logger: RequestLogger): BodyParserErrorHandler {
  return (error, request, response, next): void => {
    const statusCode = resolveBodyParserStatus(error);

    if (statusCode === undefined) {
      next(error);
      return;
    }

    const requestId = getRequestId(request);
    const path = (request.originalUrl || request.url || '').split('?')[0];

    logger.warn({
      err: error,
      msg: 'request rejected before routing',
      requestId,
      statusCode,
      method: request.method,
      path,
    });

    if (response.headersSent) {
      return;
    }

    response.status(statusCode).json(toErrorResponseBody(statusCode, requestId));
  };
}
