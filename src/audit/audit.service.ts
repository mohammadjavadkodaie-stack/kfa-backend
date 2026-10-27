import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import type { AuditLog, Prisma } from '@prisma/client';
import { createHmac, randomUUID } from 'node:crypto';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { PrismaService } from '../database/prisma.service';
import { computeAuditHash, isAuditHash, nextAuditTimestamp } from './audit-canonical';
import { redactMetadata } from './audit-redaction';

/**
 * Advisory-lock coordinates for the hash chain (`pg_advisory_xact_lock`).
 * 0x4B4641 is "KFA" in ASCII; the second key identifies the audit chain so
 * future chains can lock independently. Constant across all instances, which is
 * what serialises concurrent inserts into a single, unbroken chain.
 */
export const AUDIT_CHAIN_LOCK_NAMESPACE = 4_933_185;
export const AUDIT_CHAIN_LOCK_ID = 1;

const MAX_ACTOR_ROLE_LENGTH = 64;
const MAX_ACTION_LENGTH = 200;
const MAX_TARGET_TYPE_LENGTH = 100;
const MAX_TARGET_ID_LENGTH = 200;
const MAX_REQUEST_ID_LENGTH = 200;
const MAX_IP_LENGTH = 64;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
/** Printable ASCII without spaces: action / role / id style tokens. */
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

/** Fields a caller may set. Hash, prevHash, id, createdAt are never accepted. */
export interface AuditRecordInput {
  readonly action: string;
  readonly actorId?: string | null;
  readonly actorRole?: string | null;
  readonly targetType?: string | null;
  readonly targetId?: string | null;
  readonly requestId?: string | null;
  /**
   * Raw client IP. It is HMAC-SHA256 hashed before it leaves this method; the
   * raw value is never persisted or logged.
   */
  readonly ip?: string | null;
  /** Free-form details; sensitive keys are redacted recursively. */
  readonly metadata?: unknown;
}

function invalidField(field: string, requirement: string): never {
  // Deliberately no value in the message: audit input can contain secrets.
  throw new BadRequestException(`Invalid audit field "${field}": ${requirement}`);
}

function requireText(field: string, value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    invalidField(field, `expected a string of 1-${maxLength} characters`);
  }

  if (!TOKEN_PATTERN.test(value)) {
    invalidField(field, 'expected printable characters without whitespace');
  }

  return value;
}

function optionalText(field: string, value: unknown, maxLength: number): string | null {
  if (value === undefined || value === null) {
    return null;
  }

  return requireText(field, value, maxLength);
}

function optionalUuid(field: string, value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    invalidField(field, 'expected a UUID');
  }

  return value;
}

function hashClientIp(hmacKey: string, ip: unknown): string | null {
  if (ip === undefined || ip === null) {
    return null;
  }

  if (typeof ip !== 'string' || ip.length === 0 || ip.length > MAX_IP_LENGTH) {
    invalidField('ip', `expected a string of 1-${MAX_IP_LENGTH} characters`);
  }

  return createHmac('sha256', hmacKey).update(ip).digest('hex');
}

/**
 * Append-only audit trail. This service exposes `record` and nothing else: no
 * update, no delete, no truncate. The database rejects them independently.
 */
@Injectable()
export class AuditService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  /**
   * Appends one row inside a single transaction:
   *   advisory xact lock -> read last hash -> compute hash -> insert.
   *
   * READ COMMITTED is correct here: every statement after the lock acquisition
   * takes a fresh snapshot, so the chain head is always current. The lock is
   * released automatically at commit/rollback.
   */
  async record(input: AuditRecordInput): Promise<AuditLog> {
    const action = requireText('action', input.action, MAX_ACTION_LENGTH);
    const actorId = optionalUuid('actorId', input.actorId);
    const actorRole = optionalText('actorRole', input.actorRole, MAX_ACTOR_ROLE_LENGTH);
    const targetType = optionalText('targetType', input.targetType, MAX_TARGET_TYPE_LENGTH);
    const targetId = optionalText('targetId', input.targetId, MAX_TARGET_ID_LENGTH);
    const requestId = optionalText('requestId', input.requestId, MAX_REQUEST_ID_LENGTH);
    const ipHash = hashClientIp(this.env.AUDIT_HMAC_KEY, input.ip);
    const metadata = redactMetadata(input.metadata ?? {});

    return this.prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT pg_advisory_xact_lock(${AUDIT_CHAIN_LOCK_NAMESPACE}::int, ${AUDIT_CHAIN_LOCK_ID}::int)`;

        const last = await tx.auditLog.findFirst({
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          select: { hash: true, createdAt: true },
        });

        if (last !== null && !isAuditHash(last.hash)) {
          // Fail closed rather than extend a chain we cannot verify.
          throw new Error('Audit hash chain is corrupt: last row has an invalid hash');
        }

        const id = randomUUID();
        const createdAt = nextAuditTimestamp(last?.createdAt ?? null);
        const prevHash = last?.hash ?? null;
        const hash = computeAuditHash(prevHash, {
          id,
          createdAt,
          actorId,
          actorRole,
          action,
          targetType,
          targetId,
          requestId,
          ipHash,
          metadata,
        });

        return tx.auditLog.create({
          data: {
            id,
            createdAt,
            actorId,
            actorRole,
            action,
            targetType,
            targetId,
            requestId,
            ipHash,
            metadata: metadata as unknown as Prisma.InputJsonValue,
            prevHash,
            hash,
          },
        });
      },
      { maxWait: 5_000, timeout: 10_000 },
    );
  }
}
