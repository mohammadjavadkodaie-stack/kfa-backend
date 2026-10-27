import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

export const REQUEST_ID_HEADER = 'x-request-id';

/**
 * Canonical UUID (any RFC 4122 version, variants 8/9/a/b).
 * Anything else coming from a client is discarded.
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function resolveRequestId(headerValue: string | string[] | undefined): string {
  const candidate = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  return isUuid(candidate) ? candidate.toLowerCase() : randomUUID();
}

/** Reads the id assigned by `requestIdMiddleware` (or by pino-http). */
export function getRequestId(request: { id?: unknown }): string {
  return typeof request.id === 'string' && request.id.length > 0 ? request.id : 'unknown';
}

/**
 * Assigns a trusted request id and echoes it on the response. A client-supplied
 * `x-request-id` is only honoured when it is a valid UUID, which prevents log
 * injection / correlation spoofing.
 */
export function requestIdMiddleware(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  const requestId = resolveRequestId(request.headers[REQUEST_ID_HEADER]);

  (request as Request & { id?: string }).id = requestId;
  response.setHeader(REQUEST_ID_HEADER, requestId);

  next();
}
