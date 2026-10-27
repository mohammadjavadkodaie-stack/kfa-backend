import { createHash } from 'node:crypto';

/**
 * Canonicalisation + hashing for the audit hash chain.
 *
 * The stored hash is `sha256(prevHash + canonicalJson(rowFields))`. The
 * canonical form is deterministic across processes and across Postgres
 * round-trips: object keys are sorted, absent values become `null`, dates are
 * ISO-8601 strings and arrays keep their order.
 *
 * Values in `metadata` may come back from `jsonb` with a different key order,
 * so sorting keys is what makes the chain verifiable after reading rows again.
 */

const AUDIT_HASH_HEX_LENGTH = 64;
export const AUDIT_HASH_PATTERN = /^[0-9a-f]{64}$/;

function canonicalize(value: unknown, seen: WeakSet<object>): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      // Non-finite numbers are not valid JSON. Metadata is normalised to `null`
      // before it reaches this function, so this is only a safety net.
      return Number.isFinite(value) ? JSON.stringify(value) : 'null';
    case 'string':
      return JSON.stringify(value);
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object':
      break;
    default:
      return 'null';
  }

  const objectValue = value as object;

  if (seen.has(objectValue)) {
    throw new TypeError('Cannot canonicalise circular metadata');
  }

  seen.add(objectValue);

  try {
    if (value instanceof Date) {
      return JSON.stringify(value.toISOString());
    }

    if (Array.isArray(value)) {
      return `[${value.map((item) => canonicalize(item, seen)).join(',')}]`;
    }

    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();

    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key], seen)}`)
      .join(',')}}`;
  } finally {
    seen.delete(objectValue);
  }
}

/** Deterministic JSON string (sorted keys, recursive). */
export function canonicalJson(value: unknown): string {
  return canonicalize(value, new WeakSet<object>());
}

/** Immutable fields covered by the hash chain (never taken from the caller). */
export interface AuditHashPayload {
  readonly id: string;
  readonly createdAt: Date;
  readonly actorId: string | null;
  readonly actorRole: string | null;
  readonly action: string;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly requestId: string | null;
  readonly ipHash: string | null;
  readonly metadata: unknown;
}

export function serializeAuditPayload(payload: AuditHashPayload): string {
  return canonicalJson({
    id: payload.id,
    createdAt: payload.createdAt.toISOString(),
    actorId: payload.actorId,
    actorRole: payload.actorRole,
    action: payload.action,
    targetType: payload.targetType,
    targetId: payload.targetId,
    requestId: payload.requestId,
    ipHash: payload.ipHash,
    metadata: payload.metadata,
  });
}

/**
 * hash = sha256(prevHash || canonicalJson(rowFields)).
 * An absent prevHash (first row) is the empty string, which is unambiguous
 * because every real hash is exactly 64 lowercase hex characters.
 */
export function computeAuditHash(prevHash: string | null, payload: AuditHashPayload): string {
  if (prevHash !== null && !AUDIT_HASH_PATTERN.test(prevHash)) {
    throw new Error('prevHash must be null or a 64 character lowercase hex digest');
  }

  return createHash('sha256')
    .update(prevHash ?? '')
    .update(serializeAuditPayload(payload))
    .digest('hex');
}

export function isAuditHash(value: string): boolean {
  return value.length === AUDIT_HASH_HEX_LENGTH && AUDIT_HASH_PATTERN.test(value);
}

/**
 * Keeps `createdAt` strictly increasing so that ordering by `created_at`
 * always matches insertion (= chain) order, even when two transactions start in
 * the same millisecond. Callers hold the advisory lock while computing this.
 */
export function nextAuditTimestamp(previous: Date | null, now: Date = new Date()): Date {
  if (previous === null) {
    return now;
  }

  return new Date(Math.max(now.getTime(), previous.getTime() + 1));
}
