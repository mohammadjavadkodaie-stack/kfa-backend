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
}

export function genericMessageFor(statusCode: number): string {
  return GENERIC_MESSAGES[statusCode] ?? 'Request failed';
}

export function toErrorResponseBody(statusCode: number, requestId: string): ErrorResponseBody {
  return {
    statusCode,
    message: genericMessageFor(statusCode),
    requestId,
  };
}
