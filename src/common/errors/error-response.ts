/**
 * Client-facing error shape.
 *
 * Every failure leaves the API in exactly this shape: a numeric status, a
 * generic message and the request id. Internal details (stack traces, SQL,
 * framework messages) stay in server-side logs.
 */

const GENERIC_MESSAGES: Readonly<Record<number, string>> = Object.freeze({
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  409: 'Conflict',
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
});

export interface ErrorResponseBody {
  readonly statusCode: number;
  readonly message: string;
  readonly requestId: string;
  /**
   * Present only when the client has to act, today just `step_up_required`.
   * Everything else stays generic, so failures remain indistinguishable.
   */
  readonly code?: string;
}

/** The only code the envelope may carry; anything else is dropped. */
export const STEP_UP_REQUIRED_CODE = 'step_up_required';

const PUBLIC_CODES: ReadonlySet<string> = new Set([STEP_UP_REQUIRED_CODE]);

export function genericMessageFor(statusCode: number): string {
  return GENERIC_MESSAGES[statusCode] ?? 'Request failed';
}

export function toErrorResponseBody(
  statusCode: number,
  requestId: string,
  code?: string,
): ErrorResponseBody {
  const body = { statusCode, message: genericMessageFor(statusCode), requestId };

  return code !== undefined && PUBLIC_CODES.has(code) ? { ...body, code } : body;
}

/** Minimal exception surface, so this helper stays framework-agnostic. */
interface ExceptionLike {
  getResponse?(): unknown;
}

/** Reads an allow-listed code out of an exception payload; never any message. */
export function readPublicErrorCode(exception: unknown): string | undefined {
  if (typeof exception !== 'object' || exception === null) return undefined;

  const getResponse = (exception as ExceptionLike).getResponse;

  if (typeof getResponse !== 'function') return undefined;

  let payload: unknown;

  try {
    payload = getResponse.call(exception);
  } catch {
    return undefined;
  }

  if (typeof payload !== 'object' || payload === null || !('code' in payload)) return undefined;

  const code = (payload as { code?: unknown }).code;

  return typeof code === 'string' && PUBLIC_CODES.has(code) ? code : undefined;
}

/** Minimal response/request surface, so this helper stays framework-agnostic. */
interface ResponseLike {
  setHeader(name: string, value: string): unknown;
  status(code: number): unknown;
}

interface RequestLike {
  id?: unknown;
}

/**
 * Writes the generic 429 envelope plus the retry hint. Shared by every
 * controller that has to answer a rate-limit decision, so the shape and the
 * `Retry-After` rounding cannot drift apart.
 */
export function writeTooManyRequests(
  response: ResponseLike,
  request: RequestLike,
  retryAfterSeconds: number,
): ErrorResponseBody {
  response.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfterSeconds))));
  response.status(429);

  return toErrorResponseBody(429, typeof request.id === 'string' ? request.id : 'unknown');
}
