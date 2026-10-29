import { randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';
import type { Params } from 'nestjs-pino';
import { stdSerializers } from 'pino';
import type { Env } from '../config/env';

const REDACTED = '[REDACTED]';

/** Header-based credentials that must never appear in a log line. */
const SENSITIVE_HEADER_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'req.headers["set-cookie"]',
  'res.headers["set-cookie"]',
] as const;

/** Body/context fields (any nesting level up to 3) that must be redacted. */
const SENSITIVE_FIELDS = [
  'password',
  'code',
  'otp',
  'token',
  'cookie',
  'accessToken',
  'refreshToken',
  'idNumber',
  'cardNumber',
  'captchaToken',
  'proof',
  'otpProof',
] as const;

/**
 * Client IPs in explicit log calls. The HTTP access line keeps its
 * `remoteAddress` on purpose (that is the request log), but an IP must never be
 * copied into an ad-hoc context object: use a hash or omit it.
 */
const SENSITIVE_IP_PATHS = ['ip', '*.ip', '*.*.ip'] as const;

const WILDCARD_PREFIXES = ['', '*.', '*.*.', '*.*.*.'] as const;

/**
 * Connection strings / secrets that could be logged by accident (startup
 * diagnostics, error context). Whole values are censored; the variable name
 * stays visible so the log line is still actionable.
 */
const SENSITIVE_CONFIG_PATHS = [
  'DATABASE_URL',
  'MIGRATION_DATABASE_URL',
  'REDIS_URL',
  'AUDIT_HMAC_KEY',
  'RATE_LIMIT_HMAC_KEY',
  'OTP_PROOF_SECRET',
  'ACCESS_TOKEN_SECRET',
] as const;

export function buildRedactPaths(): string[] {
  const paths = new Set<string>(SENSITIVE_HEADER_PATHS);

  // Whole payloads are never logged, even if they somehow end up in a log call.
  paths.add('req.body');
  paths.add('res.body');

  for (const field of SENSITIVE_FIELDS) {
    paths.add(`req.body.${field}`);
    paths.add(`res.body.${field}`);

    for (const prefix of WILDCARD_PREFIXES) {
      paths.add(`${prefix}${field}`);
    }
  }

  for (const ipPath of SENSITIVE_IP_PATHS) {
    paths.add(ipPath);
  }

  for (const configPath of SENSITIVE_CONFIG_PATHS) {
    paths.add(configPath);
    paths.add(`env.${configPath}`);
  }

  return [...paths];
}

function stripQuery(url: string): string {
  return url.split('?')[0] ?? url;
}

/**
 * Structured logging configuration.
 *
 * No request bodies are logged: the request serializer only keeps the method,
 * path (without query string), remote address and the request id. Redaction is
 * still enabled as defence in depth for explicit log calls.
 */
export function buildPinoParams(env: Env): Params<Request, Response> {
  return {
    pinoHttp: {
      level: env.LOG_LEVEL,
      redact: {
        paths: buildRedactPaths(),
        censor: REDACTED,
        remove: false,
      },
      genReqId: (request) =>
        typeof request.id === 'string' && request.id.length > 0 ? request.id : randomUUID(),
      serializers: {
        req: (request: Request) => ({
          id: request.id,
          method: request.method,
          url: stripQuery(request.url),
          remoteAddress: request.ip ?? request.socket?.remoteAddress,
        }),
        res: (response: Response) => ({ statusCode: response.statusCode }),
        err: stdSerializers.err,
      },
    },
  };
}
