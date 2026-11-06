/**
 * Keeps a credential out of the request path that reaches a log line.
 *
 * `GET /documents/view/:token` carries the view link in the path, because an
 * `<img>` cannot send an `Authorization` header. A path is copied into every
 * access line (the `pino-http` request serializer) and into every error line
 * (the exception filter and the body-parser error handler), so the token would
 * outlive its single use in the log files - exactly what the one-time nonce
 * exists to prevent. Each of those three places passes the path through
 * `redactRequestPath` first, so the token is never written anywhere.
 *
 * Everything else keeps its diagnostic value: unrelated paths and the query
 * string (already removed by the callers) are returned untouched.
 */

/** The path prefix whose last segment is a credential, never a path to log. */
export const VIEW_FILE_ROUTE_PREFIX = '/documents/view/';

/** What a log line shows instead of the real token: the route pattern. */
export const VIEWED_FILE_ROUTE_PATTERN = `${VIEW_FILE_ROUTE_PREFIX}:token`;

/** One or more path segments after the prefix, up to the query or a fragment. */
const VIEW_FILE_PATH = /\/documents\/view\/[^/?#]+/g;

/** Replaces any view token in `path` with the `:token` route pattern. */
export function redactRequestPath(path: string): string {
  return path.replace(VIEW_FILE_PATH, VIEWED_FILE_ROUTE_PATTERN);
}
