import { z } from 'zod';

/**
 * Environment contract for the API.
 *
 * Everything is validated once at boot (fail fast). Error messages only ever
 * reference variable NAMES - values are never echoed back or logged.
 */

const NODE_ENVS = ['development', 'test', 'production'] as const;
const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;

/** Minimum / maximum accepted request body size (1 KiB - 1 MiB). */
export const BODY_LIMIT_BYTES_MIN = 1024;
export const BODY_LIMIT_BYTES_MAX = 1024 * 1024;

const httpOriginSchema = z.string().transform((value, ctx) => {
  let url: URL;

  try {
    url = new URL(value.trim());
  } catch {
    ctx.addIssue({ code: 'custom', message: 'must be an absolute http(s) origin' });
    return z.NEVER;
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    ctx.addIssue({ code: 'custom', message: 'must use the http or https scheme' });
    return z.NEVER;
  }

  if (
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hostname === '*'
  ) {
    ctx.addIssue({
      code: 'custom',
      message: 'must be an origin only (no path, query, hash, credentials or wildcard)',
    });
    return z.NEVER;
  }

  return url.origin;
});

const appOriginsSchema = z
  .string()
  .superRefine((value, ctx) => {
    if (value.trim().length === 0) {
      ctx.addIssue({ code: 'custom', message: 'must list at least one origin' });
    }
  })
  .transform((value) =>
    value
      .split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0),
  )
  .pipe(z.array(httpOriginSchema).min(1).max(20))
  .transform((origins) => [...new Set(origins)]);

export const envSchema = z.object({
  NODE_ENV: z.enum(NODE_ENVS).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  APP_ORIGINS: appOriginsSchema,
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  TRUSTED_PROXY_COUNT: z.coerce.number().int().min(0).max(10).default(0),
  BODY_LIMIT_BYTES: z.coerce
    .number()
    .int()
    .min(BODY_LIMIT_BYTES_MIN)
    .max(BODY_LIMIT_BYTES_MAX)
    .default(100 * 1024),
});

export type Env = Readonly<z.infer<typeof envSchema>>;

function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
    .join('\n');
}

/**
 * Parses and validates the environment. Throws (never returns a partial
 * result) so the process cannot start with an unsafe configuration.
 */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);

  if (!result.success) {
    throw new Error(`Invalid environment configuration:\n${formatIssues(result.error)}`);
  }

  return Object.freeze(result.data);
}
