import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { parseRole, Role } from './roles';
import type {
  AccountRecord,
  ActiveSessionRecord,
  AdminUserRecord,
  ChangePhoneInput,
  ChangePhoneResult,
  CreateAccountInput,
  CreateSessionInput,
  IssuedSessionRecord,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
  SessionRepository,
  SessionSummaryRecord,
} from './session.repository';

/** A row returned by the atomic consume statement. */
interface ConsumedRow {
  readonly session_id: string;
  readonly user_id: string;
  readonly user_status: string;
  readonly user_role: string;
  readonly last_used_at: Date;
  readonly device_key_hash: string;
  readonly device_bound: boolean;
  readonly session_expires_at: Date;
}

/** Prisma's generated Role and our Role carry the same four names. */
const PRISMA_ROLE: Record<Role, 'USER' | 'ATHLETE' | 'ADMIN' | 'OWNER'> = {
  [Role.USER]: 'USER',
  [Role.ATHLETE]: 'ATHLETE',
  [Role.ADMIN]: 'ADMIN',
  [Role.OWNER]: 'OWNER',
};

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error
    ? (error as { code: unknown }).code === 'P2002'
    : false;
}

@Injectable()
export class PrismaSessionRepository implements SessionRepository {
  constructor(private readonly prisma: PrismaService) {}

  async isUsernameTaken(username: string): Promise<boolean> {
    const existing = await this.prisma.user.findFirst({
      where: { username: { equals: username, mode: 'insensitive' } },
      select: { id: true },
    });

    return existing !== null;
  }

  async findUserByPhone(phoneE164: string): Promise<AccountRecord | null> {
    const user = await this.prisma.user.findUnique({
      where: { phone: phoneE164 },
      select: { id: true, status: true, role: true },
    });

    if (user === null) return null;

    // Same fail-closed rule as the guard: an unknown role owns no session.
    const role = parseRole(user.role);

    return role === null ? null : { id: user.id, status: user.status, role };
  }

  async findPhoneByUserId(userId: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { phone: true },
    });

    return user === null ? null : user.phone;
  }

  async findUsernameByUserId(userId: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { username: true },
    });

    return user === null ? null : user.username;
  }

  async findUserById(userId: string): Promise<AdminUserRecord | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, role: true, status: true },
    });

    if (user === null) return null;

    // A stored value outside the enum cannot happen through Prisma; fail closed
    // instead of handing an unknown role to the policy layer.
    const role = parseRole(user.role);

    return role === null ? null : { id: user.id, role, status: user.status };
  }

  /**
   * One UPDATE with the old value in the predicate. PostgreSQL re-checks the
   * predicate against the committed row, so of two callers that read the same
   * value exactly one changes a row.
   */
  async setStatusIf(
    userId: string,
    expectedStatus: 'ACTIVE' | 'BLOCKED',
    newStatus: 'ACTIVE' | 'BLOCKED',
  ): Promise<boolean> {
    const updated = await this.prisma.user.updateMany({
      where: { id: userId, status: expectedStatus },
      data: { status: newStatus },
    });

    return updated.count === 1;
  }

  async setRoleIf(userId: string, expectedRole: Role, newRole: Role): Promise<boolean> {
    const updated = await this.prisma.user.updateMany({
      where: { id: userId, role: PRISMA_ROLE[expectedRole] },
      data: { role: PRISMA_ROLE[newRole] },
    });

    return updated.count === 1;
  }

  /** Null means "phone or username already exists"; the caller stays generic. */
  async createAccount(input: CreateAccountInput): Promise<IssuedSessionRecord | null> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        await tx.user.create({
          data: {
            id: input.userId,
            phone: input.phone,
            username: input.username,
            // The OTP proof is what proves the number, so it is verified now.
            phoneVerifiedAt: input.now,
          },
        });

        const device = await tx.device.create({
          data: {
            userId: input.userId,
            deviceKeyHash: input.deviceKeyHash,
            label: input.deviceLabel,
          },
        });

        const session = await tx.session.create({
          data: {
            userId: input.userId,
            deviceId: device.id,
            deviceBound: input.deviceBound,
            expiresAt: input.sessionExpiresAt,
          },
        });

        await tx.refreshToken.create({
          data: {
            sessionId: session.id,
            tokenHash: input.refreshTokenHash,
            expiresAt: input.refreshExpiresAt,
          },
        });

        return {
          userId: input.userId,
          sessionId: session.id,
          deviceKeyHash: input.deviceKeyHash,
          deviceBound: input.deviceBound,
          sessionExpiresAt: input.sessionExpiresAt,
          refreshExpiresAt: input.refreshExpiresAt,
        };
      });
    } catch (error) {
      if (isUniqueViolation(error)) return null;
      throw error;
    }
  }

  async createSession(input: CreateSessionInput): Promise<IssuedSessionRecord> {
    return this.prisma.$transaction(async (tx) => {
      // Serialise concurrent logins of one user, so two cannot both see room.
      // The cast is required: tagged-template parameters arrive as text, and
      // PostgreSQL has no `uuid = text` operator.
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${input.userId}::uuid FOR UPDATE`;

      const active = await tx.session.count({
        where: { userId: input.userId, revokedAt: null, expiresAt: { gt: input.now } },
      });
      const excess = active + 1 - input.maxActiveSessions;

      if (excess > 0) {
        // Oldest first: the cap drops the sessions the user is least likely to use.
        const oldest = await tx.session.findMany({
          where: { userId: input.userId, revokedAt: null, expiresAt: { gt: input.now } },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          take: excess,
          select: { id: true },
        });
        const ids = oldest.map((session) => session.id);

        await tx.session.updateMany({
          where: { id: { in: ids } },
          data: { revokedAt: input.now, revokedReason: 'session_cap' },
        });

        await tx.refreshToken.updateMany({
          where: { sessionId: { in: ids }, revokedAt: null },
          data: { revokedAt: input.now },
        });
      }

      const device = await tx.device.upsert({
        where: { deviceKeyHash: input.deviceKeyHash },
        create: {
          userId: input.userId,
          deviceKeyHash: input.deviceKeyHash,
          label: input.deviceLabel,
        },
        update: { lastSeenAt: input.now },
      });

      const session = await tx.session.create({
        data: {
          userId: input.userId,
          deviceId: device.id,
          deviceBound: input.deviceBound,
          expiresAt: input.sessionExpiresAt,
        },
      });

      await tx.refreshToken.create({
        data: {
          sessionId: session.id,
          tokenHash: input.refreshTokenHash,
          expiresAt: input.refreshExpiresAt,
        },
      });

      return {
        userId: input.userId,
        sessionId: session.id,
        deviceKeyHash: input.deviceKeyHash,
        deviceBound: input.deviceBound,
        sessionExpiresAt: input.sessionExpiresAt,
        refreshExpiresAt: input.refreshExpiresAt,
      };
    });
  }

  /**
   * One statement decides the race: the row lock taken by the update is what
   * makes a second refresh with the same token see zero rows.
   */
  async rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult> {
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<ConsumedRow[]>`
        UPDATE refresh_tokens AS rt
           SET used_at = ${input.now}
          FROM sessions AS s
          JOIN devices AS d ON d.id = s.device_id
          JOIN users AS u ON u.id = s.user_id
         WHERE s.id = rt.session_id
           AND rt.token_hash = ${input.tokenHash}
           AND rt.used_at IS NULL
           AND rt.revoked_at IS NULL
           AND rt.expires_at > ${input.now}
           AND s.revoked_at IS NULL
           AND s.expires_at > ${input.now}
        RETURNING rt.id, s.id AS session_id, s.user_id, u.status AS user_status,
                  u.role AS user_role, s.last_used_at, d.device_key_hash, s.device_bound,
                  s.expires_at AS session_expires_at
      `;

      const consumed = rows[0];

      if (consumed === undefined) {
        // A zero-row update is either an unknown token or a replayed one; only
        // the second case means someone else already rotated this chain.
        const existing = await tx.refreshToken.findUnique({
          where: { tokenHash: input.tokenHash },
          select: { usedAt: true, revokedAt: true, session: { select: { userId: true } } },
        });

        return existing !== null && existing.usedAt !== null && existing.revokedAt === null
          ? { outcome: 'reused', userId: existing.session.userId }
          : { outcome: 'unknown' };
      }

      const sessionExpiresAt = new Date(consumed.session_expires_at);
      const refreshExpiresAt = new Date(
        Math.min(input.now.getTime() + input.refreshTtlMs, sessionExpiresAt.getTime()),
      );

      await tx.refreshToken.create({
        data: {
          sessionId: consumed.session_id,
          tokenHash: input.nextTokenHash,
          expiresAt: refreshExpiresAt,
        },
      });

      await tx.session.update({
        where: { id: consumed.session_id },
        data: { lastUsedAt: input.now },
      });

      return {
        outcome: 'rotated',
        userId: consumed.user_id,
        sessionId: consumed.session_id,
        deviceKeyHash: consumed.device_key_hash,
        deviceBound: consumed.device_bound,
        userStatus: consumed.user_status === 'BLOCKED' ? 'BLOCKED' : 'ACTIVE',
        // An unmapped role cannot be staff, so it stays on the normal policy.
        role: parseRole(consumed.user_role) ?? Role.USER,
        lastUsedAt: new Date(consumed.last_used_at),
        sessionExpiresAt,
        refreshExpiresAt,
      };
    });
  }

  async revokeSession(sessionId: string, reason: string, now: Date): Promise<void> {
    await this.prisma.session.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt: now, revokedReason: reason },
    });
  }

  async revokeUserSession(
    sessionId: string,
    userId: string,
    reason: string,
    now: Date,
  ): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const revoked = await tx.session.updateMany({
        where: { id: sessionId, userId, revokedAt: null },
        data: { revokedAt: now, revokedReason: reason },
      });

      // Unknown, foreign and already revoked sessions all update zero rows.
      if (revoked.count === 0) return false;

      await tx.refreshToken.updateMany({
        where: { sessionId, revokedAt: null },
        data: { revokedAt: now },
      });

      return true;
    });
  }

  async listActiveSessions(userId: string, now: Date): Promise<SessionSummaryRecord[]> {
    const rows = await this.prisma.session.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: now } },
      orderBy: [{ lastUsedAt: 'desc' }, { id: 'asc' }],
      select: {
        id: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
        device: { select: { label: true } },
      },
    });

    return rows.map((row) => ({
      id: row.id,
      deviceLabel: row.device.label,
      createdAt: row.createdAt,
      lastUsedAt: row.lastUsedAt,
      expiresAt: row.expiresAt,
    }));
  }

  async revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now, revokedReason: reason },
      });

      await tx.refreshToken.updateMany({
        where: { revokedAt: null, session: { userId } },
        data: { revokedAt: now },
      });
    });
  }

  async revokeOtherUserSessions(
    userId: string,
    keepSessionId: string,
    reason: string,
    now: Date,
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.session.updateMany({
        where: { userId, id: { not: keepSessionId }, revokedAt: null },
        data: { revokedAt: now, revokedReason: reason },
      });

      await tx.refreshToken.updateMany({
        where: {
          revokedAt: null,
          session: { userId, id: { not: keepSessionId } },
        },
        data: { revokedAt: now },
      });
    });
  }

  /**
   * Writes the new number first, so a taken number is refused by the unique
   * index instead of a read that a concurrent registration would invalidate.
   * The session revocations share the transaction: a failure anywhere leaves
   * the account on its old number.
   */
  async changePhone(input: ChangePhoneInput): Promise<ChangePhoneResult> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        const updated = await tx.user.updateMany({
          where: { id: input.userId },
          data: { phone: input.phone, phoneVerifiedAt: input.now },
        });

        if (updated.count === 0) return { outcome: 'not_found' };

        // Every session but the one that asked, plus their refresh tokens: a
        // stolen session must not survive the change meant to lock it out.
        const others = input.keepSessionId === null ? {} : { id: { not: input.keepSessionId } };

        const sessions = await tx.session.updateMany({
          where: { userId: input.userId, ...others, revokedAt: null },
          data: { revokedAt: input.now, revokedReason: 'phone_changed' },
        });

        await tx.refreshToken.updateMany({
          where: { revokedAt: null, session: { userId: input.userId, ...others } },
          data: { revokedAt: input.now },
        });

        return { outcome: 'changed', revokedSessions: sessions.count };
      });
    } catch (error) {
      if (isUniqueViolation(error)) return { outcome: 'conflict' };
      throw error;
    }
  }

  async revokeSessionByRefreshTokenHash(
    tokenHash: string,
    reason: string,
    now: Date,
  ): Promise<string | null> {
    const token = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      select: { sessionId: true, session: { select: { userId: true } } },
    });

    if (token === null) return null;

    await this.revokeSession(token.sessionId, reason, now);

    return token.session.userId;
  }

  /**
   * One query, not two: the session row is joined with its owner so the guard
   * sees the current role and verifier flag at the same cost as the old
   * liveness check.
   */
  async findActiveSession(
    sessionId: string,
    userId: string,
    now: Date,
  ): Promise<ActiveSessionRecord | null> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId, revokedAt: null, expiresAt: { gt: now } },
      select: {
        id: true,
        userId: true,
        user: { select: { role: true, identityVerifier: true, status: true } },
      },
    });

    if (session === null) return null;

    // A value outside the enum cannot happen through Prisma; fail closed if it
    // ever does instead of handing an unknown role to the policy layer.
    const role = parseRole(session.user.role);

    if (role === null) return null;

    return {
      sessionId: session.id,
      userId: session.userId,
      role,
      identityVerifier: session.user.identityVerifier,
      status: session.user.status,
    };
  }

  /** Same liveness condition as findActiveSession, one column wide. */
  async getStepUpAt(sessionId: string, userId: string): Promise<Date | null> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId, revokedAt: null, expiresAt: { gt: new Date() } },
      select: { stepupAt: true },
    });

    return session === null ? null : session.stepupAt;
  }

  /**
   * One statement, so the row the guard will read next is the row this wrote.
   * The database clock keeps the stamp valid even if an app host drifts.
   */
  async markStepUp(sessionId: string, userId: string): Promise<boolean> {
    const updated = await this.prisma.$executeRaw`
      UPDATE "sessions"
         SET "stepup_at" = now()
       WHERE "id" = ${sessionId}::uuid
         AND "user_id" = ${userId}::uuid
         AND "revoked_at" IS NULL
         AND "expires_at" > now()
    `;

    return updated === 1;
  }
}
