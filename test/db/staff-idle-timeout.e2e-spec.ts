import { UnauthorizedException } from '@nestjs/common';
import type { PrismaClient } from '@prisma/client';
import { randomBytes, randomUUID } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import { AuthService, type AuthRequestContext } from '../../src/auth/auth.service';
import { PrismaSessionRepository } from '../../src/auth/prisma-session.repository';
import type { ProofTokenService } from '../../src/auth/otp/proof-token';
import { Role } from '../../src/auth/roles';
import {
  generateRefreshToken,
  hashRefreshToken,
  REFRESH_COOKIE_NAME,
} from '../../src/auth/token/refresh-token';
import type { PrismaService } from '../../src/database/prisma.service';
import type { RateLimitDecision, RateLimitService } from '../../src/rate-limit/rate-limit.service';
import { createTestAuditService, createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * The staff idle limit against a real PostgreSQL.
 *
 * The refusal depends on one ordering guarantee of `rotateRefreshToken`: the
 * raw consume statement returns `sessions.last_used_at` as it was *before* the
 * rotation, and the new stamp is written afterwards. Only a real database can
 * show that `RETURNING` of the joined session row is the old value, so these
 * cases run the repository and the service exactly as the API does. Point
 * `DATABASE_URL_TEST` at a throwaway database to run them.
 */

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
/** The values the suite-owned AuthService is configured with. */
const STAFF_IDLE_MINUTES = 30;
const STAFF_ABSOLUTE_HOURS = 12;
const SESSION_ABSOLUTE_DAYS = 30;
/** Test-only signing key: never a real secret. */
const ACCESS_TOKEN_SECRET = 'db-test-access-token-secret-0123456789abcdef';

const hash = () => randomBytes(32).toString('hex');

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '7')
    .slice(0, 7)}`;
}

function username(): string {
  return `idle_${randomUUID().replaceAll('-', '')}`.slice(0, 30);
}

/** The idle check is the subject here, so the explicit limiter always admits. */
class PermissiveRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
}

/** Log lines are not assertions; the audit row comes from the real service. */
class QuietLogger {
  info(): void {}

  warn(): void {}
}

describeWithDatabase('staff idle timeout (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let sessions: PrismaSessionRepository;
  let auth: AuthService;
  const seededUsers: string[] = [];

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    sessions = new PrismaSessionRepository(prisma as unknown as PrismaService);
    auth = new AuthService(
      {
        ACCESS_TOKEN_SECRET,
        ACCESS_TOKEN_TTL_SECONDS: 600,
        REFRESH_TTL_DAYS: 14,
        SESSION_ABSOLUTE_DAYS,
        STAFF_SESSION_ABSOLUTE_HOURS: STAFF_ABSOLUTE_HOURS,
        STAFF_SESSION_IDLE_MINUTES: STAFF_IDLE_MINUTES,
        SESSIONS_MAX_PER_USER: 10,
      },
      sessions,
      // `refresh` reads neither the proof nor the throttle, so both stay fakes.
      {} as ProofTokenService,
      new PermissiveRateLimit() as unknown as RateLimitService,
      createTestAuditService(prisma),
      new QuietLogger() as unknown as PinoLogger,
    );
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: seededUsers } } });
      await prisma.$disconnect();
    }
  });

  /**
   * An account in `role` with one unused refresh token, seeded through the same
   * repository calls the API makes. The device binding stays off, so the cookie
   * is the only credential `refresh` has to check.
   */
  async function openSession(
    role: Role,
  ): Promise<{ userId: string; sessionId: string; cookie: string }> {
    const userId = randomUUID();
    const now = new Date();
    const lifetime = role === Role.USER ? SESSION_ABSOLUTE_DAYS * DAY : STAFF_ABSOLUTE_HOURS * HOUR;
    const token = generateRefreshToken();

    await prisma.user.create({
      data: { id: userId, phone: phone(), username: username(), role, phoneVerifiedAt: now },
    });
    seededUsers.push(userId);

    const issued = await sessions.createSession({
      userId,
      deviceKeyHash: hash(),
      deviceBound: false,
      deviceLabel: 'jest',
      now,
      sessionExpiresAt: new Date(now.getTime() + lifetime),
      refreshTokenHash: hashRefreshToken(token),
      refreshExpiresAt: new Date(now.getTime() + lifetime),
      maxActiveSessions: 10,
    });

    return { userId, sessionId: issued.sessionId, cookie: `${REFRESH_COOKIE_NAME}=${token}` };
  }

  /** Same fixture style as the rotation suite: pin the stored activity stamp. */
  const idleFor = async (sessionId: string, minutes: number): Promise<Date> => {
    const at = new Date(Date.now() - minutes * MINUTE);

    await prisma.session.update({ where: { id: sessionId }, data: { lastUsedAt: at } });

    return at;
  };

  const contextFor = (cookie: string, ip: string): AuthRequestContext => ({
    ip,
    deviceKey: null,
    requestId: `req-${randomUUID()}`,
    cookieHeader: cookie,
    userAgent: 'jest-agent',
  });

  it('refuses an idle ADMIN refresh and revokes the session as idle_timeout', async () => {
    const { userId, sessionId, cookie } = await openSession(Role.ADMIN);

    await idleFor(sessionId, STAFF_IDLE_MINUTES + 1);

    await expect(auth.refresh(contextFor(cookie, '198.51.100.21'))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );

    const stored = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });

    expect(stored.revokedAt).toEqual(expect.any(Date) as Date);
    expect(stored.revokedReason).toBe('idle_timeout');

    // The token really was consumed first: the refusal comes from the idle
    // check, not from an unknown-token branch that never rotated anything.
    const tokens = await prisma.refreshToken.findMany({ where: { sessionId } });

    expect(tokens).toHaveLength(2);
    expect(tokens.filter((token) => token.usedAt !== null)).toHaveLength(1);

    // The refusal is audited on the real append-only log.
    await expect(
      prisma.auditLog.findFirst({
        where: { action: 'auth.refresh.idle_timeout', actorId: userId },
      }),
    ).resolves.not.toBeNull();
  });

  it('rotates an ADMIN session just inside the idle limit and moves last_used_at forward', async () => {
    const { sessionId, cookie } = await openSession(Role.ADMIN);
    const before = await idleFor(sessionId, STAFF_IDLE_MINUTES - 1);

    const result = await auth.refresh(contextFor(cookie, '198.51.100.22'));

    expect(result.outcome).toBe('issued');

    if (result.outcome !== 'issued') throw new Error('expected issued credentials');

    expect(result.credentials.sessionId).toBe(sessionId);

    const stored = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });

    expect(stored.revokedAt).toBeNull();
    expect(stored.lastUsedAt.getTime()).toBeGreaterThan(before.getTime());
  });

  it('still rotates a USER session idle for the same time', async () => {
    const { sessionId, cookie } = await openSession(Role.USER);
    const before = await idleFor(sessionId, STAFF_IDLE_MINUTES + 1);

    const result = await auth.refresh(contextFor(cookie, '198.51.100.23'));

    expect(result.outcome).toBe('issued');

    const stored = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });

    expect(stored.revokedAt).toBeNull();
    expect(stored.revokedReason).toBeNull();
    expect(stored.lastUsedAt.getTime()).toBeGreaterThan(before.getTime());
  });
});
