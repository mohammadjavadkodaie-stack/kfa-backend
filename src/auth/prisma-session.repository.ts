import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import type {
  AccountRecord,
  CreateAccountInput,
  CreateSessionInput,
  IssuedSessionRecord,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
  SessionRepository,
} from './session.repository';

/** A row returned by the atomic consume statement. */
interface ConsumedRow {
  readonly session_id: string;
  readonly user_id: string;
  readonly user_status: string;
  readonly device_key_hash: string;
  readonly session_expires_at: Date;
}

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
    return this.prisma.user.findUnique({
      where: { phone: phoneE164 },
      select: { id: true, status: true },
    });
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
                  d.device_key_hash, s.expires_at AS session_expires_at
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
        userStatus: consumed.user_status === 'BLOCKED' ? 'BLOCKED' : 'ACTIVE',
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

  async isSessionActive(sessionId: string, userId: string, now: Date): Promise<boolean> {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId, revokedAt: null, expiresAt: { gt: now } },
      select: { id: true },
    });

    return session !== null;
  }
}
