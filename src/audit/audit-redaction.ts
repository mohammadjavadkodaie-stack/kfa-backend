/**
 * Recursive metadata redaction for the audit log.
 *
 * The check is case-insensitive and substring-based after normalising separators
 * (`refresh_token` -> `refreshtoken`). It deliberately over-redacts keys such as
 * `statusCode` or `encode`: never storing a secret is more important than a
 * perfect audit detail.
 */

export const REDACTED_VALUE = '[REDACTED]';

export const SENSITIVE_METADATA_KEYS = [
  'password',
  'code',
  'otp',
  'token',
  'refreshToken',
  'idNumber',
  'cardNumber',
  'secret',
] as const;

/** Hard stop for pathological/deep payloads. */
const MAX_REDACTION_DEPTH = 32;

export type RedactedJson =
  null | boolean | number | string | RedactedJson[] | { [key: string]: RedactedJson };

const NORMALIZED_SENSITIVE_KEYS: readonly string[] = SENSITIVE_METADATA_KEYS.map((key) =>
  key.toLowerCase().replace(/[^a-z0-9]/g, ''),
);

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function isSensitiveMetadataKey(key: string): boolean {
  const normalized = normalizeKey(key);

  return NORMALIZED_SENSITIVE_KEYS.some((sensitive) => normalized.includes(sensitive));
}

/**
 * Returns a JSON-safe copy with every sensitive value replaced by
 * `[REDACTED]`. Inputs are never mutated; undefined, functions, symbols,
 * non-finite numbers and circular references are neutralised.
 */
export function redactMetadata(
  value: unknown,
  depth = 0,
  seen: WeakSet<object> = new WeakSet<object>(),
): RedactedJson {
  if (value === null || value === undefined) {
    return null;
  }

  if (depth > MAX_REDACTION_DEPTH) {
    return REDACTED_VALUE;
  }

  switch (typeof value) {
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : null;
    case 'string':
      return value;
    case 'bigint':
      return value.toString();
    case 'object':
      break;
    default:
      return null;
  }

  const objectValue = value as object;

  if (seen.has(objectValue)) {
    return REDACTED_VALUE;
  }

  seen.add(objectValue);

  try {
    if (value instanceof Date) {
      return value.toISOString();
    }

    if (Array.isArray(value)) {
      return value.map((item) => redactMetadata(item, depth + 1, seen));
    }

    const result: Record<string, RedactedJson> = {};

    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      result[key] = isSensitiveMetadataKey(key)
        ? REDACTED_VALUE
        : redactMetadata(item, depth + 1, seen);
    }

    return result;
  } finally {
    seen.delete(objectValue);
  }
}
