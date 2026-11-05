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

/** Minimum accepted length of the audit hash-chain HMAC key. */
export const AUDIT_HMAC_KEY_MIN_LENGTH = 32;

/** Minimum accepted length of the rate-limit identifier HMAC key. */
export const RATE_LIMIT_HMAC_KEY_MIN_LENGTH = 32;

/** Minimum accepted length of the OTP proof-token HMAC secret. */
export const OTP_PROOF_SECRET_MIN_LENGTH = 32;

/** Minimum accepted length of the access-token signing secret. */
export const ACCESS_TOKEN_SECRET_MIN_LENGTH = 32;

/** Exact decoded length of the TOTP secret encryption key (AES-256). */
export const TOTP_ENC_KEY_BYTES = 32;

/** Exact decoded length of the document master key that wraps data keys (AES-256). */
export const DOCUMENT_MASTER_KEY_BYTES = 32;

/** Label assumed for the current master key when DOCUMENT_MASTER_KEY_ID is unset. */
export const DOCUMENT_MASTER_KEY_DEFAULT_ID = 'v1';

/** Short label that identifies one master-key version (`v1`, `v2`, ...). */
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;

/** Maximum accepted length of a database connection URL. */
const DATABASE_URL_MAX_LENGTH = 2048;

/** Maximum accepted length of a Redis connection URL. */
const REDIS_URL_MAX_LENGTH = 2048;

/** Maximum accepted length of an S3-compatible endpoint URL. */
const S3_ENDPOINT_MAX_LENGTH = 2048;

/** Postgres TLS modes that actually encrypt the connection. */
const TLS_REQUIRED_SSLMODES = new Set(['require', 'verify-ca', 'verify-full']);

/**
 * Validates a Redis connection string without ever echoing its value.
 * Only the shape is checked - TLS and credentials are mandatory in production
 * (see the environment-wide refinement below).
 */
const redisConnectionUrlSchema = z
  .string()
  .max(REDIS_URL_MAX_LENGTH, `must be at most ${REDIS_URL_MAX_LENGTH} characters`)
  .superRefine((value, ctx) => {
    let url: URL;

    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be a valid absolute connection URL' });
      return;
    }

    if (url.protocol !== 'redis:' && url.protocol !== 'rediss:') {
      ctx.addIssue({ code: 'custom', message: 'must use the redis or rediss scheme' });
      return;
    }

    if (url.hostname.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'must name a Redis host' });
    }

    if (url.hash.length > 0) {
      ctx.addIssue({ code: 'custom', message: 'must not contain a URL fragment' });
    }
  });

/**
 * Validates a PostgreSQL connection string without ever echoing its value.
 * Only the shape is checked - credentials and TLS policy are environment
 * specific (production additionally requires TLS, see below).
 */
const postgresConnectionUrlSchema = z
  .string()
  .max(DATABASE_URL_MAX_LENGTH, `must be at most ${DATABASE_URL_MAX_LENGTH} characters`)
  .superRefine((value, ctx) => {
    let url: URL;

    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be a valid absolute connection URL' });
      return;
    }

    if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
      ctx.addIssue({ code: 'custom', message: 'must use the postgresql scheme' });
      return;
    }

    if (url.username.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'must name a database user' });
    }

    if (url.pathname.length <= 1) {
      ctx.addIssue({ code: 'custom', message: 'must name a database' });
    }

    if (url.hash.length > 0) {
      ctx.addIssue({ code: 'custom', message: 'must not contain a URL fragment' });
    }
  });

function hasRequiredTls(url: string): boolean {
  try {
    const mode = new URL(url).searchParams.get('sslmode')?.toLowerCase();
    return mode !== undefined && TLS_REQUIRED_SSLMODES.has(mode);
  } catch {
    // Shape errors are reported by postgresConnectionUrlSchema already.
    return false;
  }
}

function redisUrlUsesTls(url: string): boolean {
  try {
    return new URL(url).protocol === 'rediss:';
  } catch {
    // Shape errors are reported by redisConnectionUrlSchema already.
    return false;
  }
}

function redisUrlHasPassword(url: string): boolean {
  try {
    return new URL(url).password.length > 0;
  } catch {
    return false;
  }
}

function s3EndpointUsesHttps(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    // Shape errors are reported by s3EndpointSchema already.
    return false;
  }
}

/**
 * True when `value` is base64url that decodes to exactly `bytes` bytes. The
 * alphabet is checked first because Buffer's decoder silently skips invalid
 * characters, which would otherwise let a typo through as a shorter key.
 */
function isBase64UrlOfLength(value: string, bytes: number): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').length === bytes;
}

/**
 * Decodes standard base64 (padding included) and returns `null` unless it holds
 * exactly `bytes` bytes. The alphabet and the length are checked first because
 * Buffer's decoder silently drops invalid characters, which would otherwise turn
 * a typo into a shorter - and therefore weaker - key.
 */
export function decodeBase64Key(value: string, bytes: number): Buffer | null {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;

  const decoded = Buffer.from(value, 'base64');

  return decoded.length === bytes ? decoded : null;
}

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

/**
 * Validates an S3-compatible endpoint without ever echoing its value.
 * Credentials, a query and a fragment are refused: they belong in the dedicated
 * S3_* variables, and a signed URL used as an endpoint would leak a secret into
 * every request.
 */
const s3EndpointSchema = z
  .string()
  .max(S3_ENDPOINT_MAX_LENGTH, `must be at most ${S3_ENDPOINT_MAX_LENGTH} characters`)
  .superRefine((value, ctx) => {
    let url: URL;

    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be a valid absolute http(s) URL' });
      return;
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      ctx.addIssue({ code: 'custom', message: 'must use the http or https scheme' });
      return;
    }

    if (url.username.length > 0 || url.password.length > 0) {
      ctx.addIssue({ code: 'custom', message: 'must not contain credentials' });
    }

    if (url.search.length > 0 || url.hash.length > 0) {
      ctx.addIssue({ code: 'custom', message: 'must not contain a query or fragment' });
    }
  })
  .transform((value) => value.trim());

export const envSchema = z
  .object({
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
    OTP_PROVIDER: z.string().min(1).default('fake'),
    CAPTCHA_PROVIDER: z.string().min(1).default('fake'),

    /**
     * Runtime connection string (role `kfa_app`, no DDL privileges).
     * Production requires an encrypted connection.
     */
    DATABASE_URL: postgresConnectionUrlSchema,

    /**
     * Migration-only connection string (role `kfa_migrator`).
     * Read by the Prisma CLI (`directUrl`); optional for the running app so a
     * deployed process never needs DDL credentials.
     */
    MIGRATION_DATABASE_URL: postgresConnectionUrlSchema.optional(),

    /** Key for HMAC-SHA256 of client IPs in the audit log (never the raw IP). */
    AUDIT_HMAC_KEY: z
      .string()
      .min(AUDIT_HMAC_KEY_MIN_LENGTH, `must be at least ${AUDIT_HMAC_KEY_MIN_LENGTH} characters`)
      .max(1024, 'must be at most 1024 characters'),

    /**
     * Shared rate-limit store (Redis). Optional outside production, where the
     * throttler falls back to in-memory storage for a single process.
     * Production requires `rediss://` (TLS) with a password.
     */
    REDIS_URL: redisConnectionUrlSchema.optional(),

    /**
     * Key for HMAC-SHA256 of rate-limit identifiers (phone/device). Raw
     * identifiers are never stored in Redis keys. Required in production.
     */
    RATE_LIMIT_HMAC_KEY: z
      .string()
      .min(
        RATE_LIMIT_HMAC_KEY_MIN_LENGTH,
        `must be at least ${RATE_LIMIT_HMAC_KEY_MIN_LENGTH} characters`,
      )
      .max(1024, 'must be at most 1024 characters')
      .optional(),

    /**
     * HMAC secret for the short-lived OTP proof token (Stage 2.3 consumes it).
     * Must be independent from the other HMAC keys so a leak of one does not
     * forge the other.
     */
    OTP_PROOF_SECRET: z
      .string()
      .min(
        OTP_PROOF_SECRET_MIN_LENGTH,
        `must be at least ${OTP_PROOF_SECRET_MIN_LENGTH} characters`,
      )
      .max(1024, 'must be at most 1024 characters')
      .optional(),

    /**
     * AES-256-GCM key that encrypts TOTP secrets at rest (Stage 3.2a).
     * Optional outside production: without it TOTP is simply unconfigured and
     * its endpoints fail closed. Required in production.
     */
    TOTP_ENC_KEY: z
      .string()
      .max(1024, 'must be at most 1024 characters')
      .superRefine((value, ctx) => {
        if (!isBase64UrlOfLength(value, TOTP_ENC_KEY_BYTES)) {
          ctx.addIssue({
            code: 'custom',
            message: `must be base64url that decodes to exactly ${TOTP_ENC_KEY_BYTES} bytes`,
          });
        }
      })
      .optional(),

    /**
     * Master key that wraps the per-document data keys (Stage 4.2a), base64 of
     * exactly 32 bytes. Optional outside production, where documents are simply
     * unconfigured; required in production.
     */
    DOCUMENT_MASTER_KEY: z
      .string()
      .max(1024, 'must be at most 1024 characters')
      .superRefine((value, ctx) => {
        if (decodeBase64Key(value, DOCUMENT_MASTER_KEY_BYTES) === null) {
          ctx.addIssue({
            code: 'custom',
            message: `must be base64 that decodes to exactly ${DOCUMENT_MASTER_KEY_BYTES} bytes`,
          });
        }
      })
      .optional(),

    /**
     * Label stored next to every wrapped data key. Optional: the wrapper falls
     * back to DOCUMENT_MASTER_KEY_DEFAULT_ID.
     */
    DOCUMENT_MASTER_KEY_ID: z
      .string()
      .regex(KEY_ID_PATTERN, 'must be a short label of letters, digits, - or _')
      .optional(),

    /**
     * Master key being rotated out. Unwrap only: new data keys are always
     * wrapped with DOCUMENT_MASTER_KEY, old blobs stay readable until they are
     * re-encrypted.
     */
    DOCUMENT_MASTER_KEY_PREVIOUS: z
      .string()
      .max(1024, 'must be at most 1024 characters')
      .superRefine((value, ctx) => {
        if (decodeBase64Key(value, DOCUMENT_MASTER_KEY_BYTES) === null) {
          ctx.addIssue({
            code: 'custom',
            message: `must be base64 that decodes to exactly ${DOCUMENT_MASTER_KEY_BYTES} bytes`,
          });
        }
      })
      .optional(),

    /** Label of the previous key; mandatory with DOCUMENT_MASTER_KEY_PREVIOUS. */
    DOCUMENT_MASTER_KEY_PREVIOUS_ID: z
      .string()
      .regex(KEY_ID_PATTERN, 'must be a short label of letters, digits, - or _')
      .optional(),

    /**
     * S3-compatible object store for encrypted documents (Stage 4.2b). The four
     * settings S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY
     * are all-or-nothing: a half-configured store is a boot error, not a surprise
     * at the first upload. None of them is required yet, not even in production,
     * because the production storage service has not been chosen.
     */
    S3_ENDPOINT: s3EndpointSchema.optional(),

    /** Signing region; defaults to us-east-1 in the adapter when unset. */
    S3_REGION: z
      .string()
      .regex(/^[a-z0-9-]{1,63}$/, 'must be a lowercase region label')
      .optional(),

    /** Bucket that holds the ciphertext. It must stay private. */
    S3_BUCKET: z
      .string()
      .regex(
        /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/,
        'must be a bucket name of 3-63 lowercase letters, digits, dots or -',
      )
      .optional(),

    /** Access key of a dedicated storage user; never an administrator key. */
    S3_ACCESS_KEY_ID: z
      .string()
      .min(1, 'must not be empty')
      .max(256, 'must be at most 256 characters')
      .optional(),

    /** Secret paired with S3_ACCESS_KEY_ID. Redacted from every log line. */
    S3_SECRET_ACCESS_KEY: z
      .string()
      .min(8, 'must be at least 8 characters')
      .max(256, 'must be at most 256 characters')
      .optional(),

    /**
     * Path-style addressing (`endpoint/bucket/key`) instead of virtual-host
     * style. MinIO needs it, AWS S3 does not. Absent stays absent and means
     * false, so the parsed object is exactly as wide as the input.
     */
    S3_FORCE_PATH_STYLE: z
      .enum(['true', 'false'], 'must be true or false')
      .optional()
      .transform((value) => (value === undefined ? undefined : value === 'true')),

    /**
     * clamd daemon that streams uploads through INSTREAM (Stage 4.3a). The host
     * and the port are all-or-nothing: one without the other is a boot error,
     * not a surprise at the first upload. Neither is required yet, not even in
     * production, because no daemon is deployed.
     */
    CLAMAV_HOST: z
      .string()
      .trim()
      .min(1, 'must name a clamd host')
      .max(255, 'must be at most 255 characters')
      .optional(),

    /** INSTREAM port of that daemon; 3310 is the clamd default. */
    CLAMAV_PORT: z.coerce.number().int().min(1).max(65535).optional(),

    /** Hard cap on OTP sends per hour across all phones (protects the provider bill). */
    OTP_GLOBAL_SENDS_PER_HOUR: z.coerce.number().int().min(1).max(100_000).default(500),

    /**
     * HS256 secret for access tokens (Stage 2.3a). Required in production and
     * independent from every other secret, so one leak cannot mint another token.
     */
    ACCESS_TOKEN_SECRET: z
      .string()
      .min(
        ACCESS_TOKEN_SECRET_MIN_LENGTH,
        `must be at least ${ACCESS_TOKEN_SECRET_MIN_LENGTH} characters`,
      )
      .max(1024, 'must be at most 1024 characters')
      .optional(),

    /** Access-token lifetime. Short by design: refresh is what keeps sessions alive. */
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(600),

    /** Lifetime of one refresh token; every rotation restarts it. */
    REFRESH_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(14),

    /** Absolute session cap: rotation can never extend a session past this. */
    SESSION_ABSOLUTE_DAYS: z.coerce.number().int().min(1).max(365).default(30),

    /**
     * Absolute cap for staff (ADMIN/OWNER) sessions, in hours. A stolen staff
     * cookie must age out long before the normal cap, so the unit is shorter.
     */
    STAFF_SESSION_ABSOLUTE_HOURS: z.coerce.number().int().min(1).max(8_760).default(12),

    /** A staff session not rotated for this long is refused at refresh time. */
    STAFF_SESSION_IDLE_MINUTES: z.coerce.number().int().min(1).max(8_760).default(30),

    /** Active sessions kept per user; a login beyond it drops the oldest one. */
    SESSIONS_MAX_PER_USER: z.coerce.number().int().min(1).max(50).default(10),
  })
  .superRefine((env, ctx) => {
    if (
      env.ACCESS_TOKEN_SECRET !== undefined &&
      [env.AUDIT_HMAC_KEY, env.RATE_LIMIT_HMAC_KEY, env.OTP_PROOF_SECRET].includes(
        env.ACCESS_TOKEN_SECRET,
      )
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['ACCESS_TOKEN_SECRET'],
        message: 'must differ from the audit, rate-limit and proof secrets',
      });
    }

    if (
      env.OTP_PROOF_SECRET !== undefined &&
      (env.OTP_PROOF_SECRET === env.AUDIT_HMAC_KEY ||
        env.OTP_PROOF_SECRET === env.RATE_LIMIT_HMAC_KEY)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['OTP_PROOF_SECRET'],
        message: 'must differ from the audit and rate-limit HMAC keys',
      });
    }

    if (
      env.TOTP_ENC_KEY !== undefined &&
      [env.AUDIT_HMAC_KEY, env.RATE_LIMIT_HMAC_KEY, env.OTP_PROOF_SECRET].includes(env.TOTP_ENC_KEY)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['TOTP_ENC_KEY'],
        message: 'must differ from the audit, rate-limit and proof secrets',
      });
    }

    // A previous key is only useful as a labelled entry: without an id it could
    // never be selected, and the same id twice would make the map ambiguous.
    if (
      (env.DOCUMENT_MASTER_KEY_PREVIOUS === undefined) !==
      (env.DOCUMENT_MASTER_KEY_PREVIOUS_ID === undefined)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['DOCUMENT_MASTER_KEY_PREVIOUS_ID'],
        message: 'must be set together with DOCUMENT_MASTER_KEY_PREVIOUS',
      });
    }

    // Object storage is all-or-nothing: a bucket without credentials (or an
    // endpoint without a bucket) would pass boot and fail on the first upload.
    const s3Required = [
      'S3_ENDPOINT',
      'S3_BUCKET',
      'S3_ACCESS_KEY_ID',
      'S3_SECRET_ACCESS_KEY',
    ] as const;
    const s3SetCount = s3Required.filter((name) => env[name] !== undefined).length;

    if (s3SetCount > 0 && s3SetCount < s3Required.length) {
      for (const name of s3Required) {
        if (env[name] === undefined) {
          ctx.addIssue({
            code: 'custom',
            path: [name],
            message: 'must be set together with the other S3 settings',
          });
        }
      }
    }

    // The virus scanner is all-or-nothing for the same reason: a host without a
    // port would pass boot and then fail on the first upload, and because the
    // ingest pipeline fails closed that would refuse every document.
    const clamavRequired = ['CLAMAV_HOST', 'CLAMAV_PORT'] as const;
    const clamavSetCount = clamavRequired.filter((name) => env[name] !== undefined).length;

    if (clamavSetCount > 0 && clamavSetCount < clamavRequired.length) {
      for (const name of clamavRequired) {
        if (env[name] === undefined) {
          ctx.addIssue({
            code: 'custom',
            path: [name],
            message: 'must be set together with the other ClamAV settings',
          });
        }
      }
    }

    if (
      env.DOCUMENT_MASTER_KEY_PREVIOUS_ID !== undefined &&
      env.DOCUMENT_MASTER_KEY_PREVIOUS_ID ===
        (env.DOCUMENT_MASTER_KEY_ID ?? DOCUMENT_MASTER_KEY_DEFAULT_ID)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['DOCUMENT_MASTER_KEY_PREVIOUS_ID'],
        message: 'must differ from DOCUMENT_MASTER_KEY_ID',
      });
    }

    // A staff session may only be shorter than a normal one, and the idle limit
    // has to leave room for at least one rotation inside the absolute cap.
    if (env.STAFF_SESSION_ABSOLUTE_HOURS * 3_600 > env.SESSION_ABSOLUTE_DAYS * 86_400) {
      ctx.addIssue({
        code: 'custom',
        path: ['STAFF_SESSION_ABSOLUTE_HOURS'],
        message: 'must not exceed SESSION_ABSOLUTE_DAYS',
      });
    }

    if (env.STAFF_SESSION_IDLE_MINUTES * 60 > env.STAFF_SESSION_ABSOLUTE_HOURS * 3_600) {
      ctx.addIssue({
        code: 'custom',
        path: ['STAFF_SESSION_IDLE_MINUTES'],
        message: 'must not exceed STAFF_SESSION_ABSOLUTE_HOURS',
      });
    }

    if (env.NODE_ENV !== 'production') {
      return;
    }

    if (!hasRequiredTls(env.DATABASE_URL)) {
      ctx.addIssue({
        code: 'custom',
        path: ['DATABASE_URL'],
        message: 'must set sslmode=require (or verify-ca / verify-full) in production',
      });
    }

    if (env.MIGRATION_DATABASE_URL !== undefined && !hasRequiredTls(env.MIGRATION_DATABASE_URL)) {
      ctx.addIssue({
        code: 'custom',
        path: ['MIGRATION_DATABASE_URL'],
        message: 'must set sslmode=require (or verify-ca / verify-full) in production',
      });
    }

    // A multi-instance deployment cannot rely on per-process counters, so the
    // shared store is mandatory and must be encrypted + authenticated.
    if (env.REDIS_URL === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['REDIS_URL'],
        message: 'is required in production (shared rate-limit store)',
      });
    } else {
      if (!redisUrlUsesTls(env.REDIS_URL)) {
        ctx.addIssue({
          code: 'custom',
          path: ['REDIS_URL'],
          message: 'must use the rediss scheme (TLS) in production',
        });
      }

      if (!redisUrlHasPassword(env.REDIS_URL)) {
        ctx.addIssue({
          code: 'custom',
          path: ['REDIS_URL'],
          message: 'must include a password in production',
        });
      }
    }

    if (env.RATE_LIMIT_HMAC_KEY === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['RATE_LIMIT_HMAC_KEY'],
        message: 'is required in production',
      });
    }

    if (env.OTP_PROOF_SECRET === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['OTP_PROOF_SECRET'],
        message: 'is required in production',
      });
    }

    if (env.TOTP_ENC_KEY === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['TOTP_ENC_KEY'],
        message: 'is required in production',
      });
    }

    if (env.ACCESS_TOKEN_SECRET === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['ACCESS_TOKEN_SECRET'],
        message: 'is required in production',
      });
    }

    if (env.DOCUMENT_MASTER_KEY === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['DOCUMENT_MASTER_KEY'],
        message: 'is required in production',
      });
    }

    // Documents are not mandatory in production yet (the production storage
    // service is still undecided), but a configured store must be reached over
    // TLS: ciphertext and the storage credentials both travel on that hop.
    if (env.S3_ENDPOINT !== undefined && !s3EndpointUsesHttps(env.S3_ENDPOINT)) {
      ctx.addIssue({
        code: 'custom',
        path: ['S3_ENDPOINT'],
        message: 'must use the https scheme in production',
      });
    }

    if (env.OTP_PROVIDER === 'fake' || env.OTP_PROVIDER === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['OTP_PROVIDER'],
        message: 'must be non-fake in production',
      });
    }
    if (env.CAPTCHA_PROVIDER === 'fake' || env.CAPTCHA_PROVIDER === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['CAPTCHA_PROVIDER'],
        message: 'must be non-fake in production',
      });
    }
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
