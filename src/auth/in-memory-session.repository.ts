import { randomUUID } from 'node:crypto';
import type {
  AccountRecord,
  CreateAccountInput,
  CreateSessionInput,
  IssuedSessionRecord,
  RotateRefreshTokenInput,
  RotateRefreshTokenResult,
  SessionRepository,
} from './session.repository';

/**
 * In-memory `SessionRepository` for unit tests.
 *
 * It reproduces the two guarantees the real repository provides - uniqueness of
 * phone/username and single-use refresh tokens - with no `await` between the
 * check and the write, which is the in-process equivalent of the row lock.
 */

interface FakeUser {
  readonly id: string;
  readonly phone: string;
  readonly username: string;
  status: 'ACTIVE' | 'BLOCKED';
}

interface FakeSession {
  readonly id: string;
  readonly userId: string;
  readonly deviceKeyHash: string;
  readonly expiresAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
  lastUsedAt: Date | null;
}

interface FakeRefreshToken {
  readonly tokenHash: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
}

export class InMemorySessionRepository implements SessionRepository {
  readonly users = new Map<string, FakeUser>();
  readonly sessions = new Map<string, FakeSession>();
  readonly refreshTokens = new Map<string, FakeRefreshToken>();
  readonly revokedSessions: { sessionId: string; reason: string }[] = [];

  /** Set to throw from `createSession`, to test error paths. */
  failNextCreateSession: Error | null = null;

  async isUsernameTaken(username: string): Promise<boolean> {
    const needle = username.toLowerCase();

    return [...this.users.values()].some((user) => user.username.toLowerCase() === needle);
  }

  async findUserByPhone(phoneE164: string): Promise<AccountRecord | null> {
    const user = [...this.users.values()].find((candidate) => candidate.phone === phoneE164);

    return user === undefined ? null : { id: user.id, status: user.status };
  }

  async createAccount(input: CreateAccountInput): Promise<IssuedSessionRecord | null> {
    const phoneTaken = [...this.users.values()].some((user) => user.phone === input.phone);
    const usernameTaken = await this.isUsernameTaken(input.username);

    if (phoneTaken || usernameTaken) return null;

    this.users.set(input.userId, {
      id: input.userId,
      phone: input.phone,
      username: input.username,
      status: 'ACTIVE',
    });

    const session = this.insertSession({
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      sessionExpiresAt: input.sessionExpiresAt,
    });

    this.insertRefreshToken(input.refreshTokenHash, session.id, input.refreshExpiresAt);

    return {
      userId: input.userId,
      sessionId: session.id,
      deviceKeyHash: input.deviceKeyHash,
      sessionExpiresAt: input.sessionExpiresAt,
      refreshExpiresAt: input.refreshExpiresAt,
    };
  }

  async createSession(input: CreateSessionInput): Promise<IssuedSessionRecord> {
    if (this.failNextCreateSession !== null) {
      const error = this.failNextCreateSession;
      this.failNextCreateSession = null;
      throw error;
    }

    const session = this.insertSession({
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      sessionExpiresAt: input.sessionExpiresAt,
    });

    this.insertRefreshToken(input.refreshTokenHash, session.id, input.refreshExpiresAt);

    return {
      userId: input.userId,
      sessionId: session.id,
      deviceKeyHash: input.deviceKeyHash,
      sessionExpiresAt: input.sessionExpiresAt,
      refreshExpiresAt: input.refreshExpiresAt,
    };
  }

  async rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult> {
    const token = this.refreshTokens.get(input.tokenHash);
    const session = token === undefined ? undefined : this.sessions.get(token.sessionId);

    if (token === undefined || session === undefined) return { outcome: 'unknown' };

    if (token.usedAt !== null && token.revokedAt === null) {
      return { outcome: 'reused', userId: session.userId };
    }

    const usable =
      token.usedAt === null &&
      token.revokedAt === null &&
      token.expiresAt.getTime() > input.now.getTime() &&
      session.revokedAt === null &&
      session.expiresAt.getTime() > input.now.getTime();

    if (!usable) return { outcome: 'unknown' };

    token.usedAt = input.now;
    session.lastUsedAt = input.now;

    const refreshExpiresAt = new Date(
      Math.min(input.now.getTime() + input.refreshTtlMs, session.expiresAt.getTime()),
    );

    this.insertRefreshToken(input.nextTokenHash, session.id, refreshExpiresAt);

    return {
      outcome: 'rotated',
      userId: session.userId,
      sessionId: session.id,
      deviceKeyHash: session.deviceKeyHash,
      userStatus: this.users.get(session.userId)?.status ?? 'BLOCKED',
      sessionExpiresAt: session.expiresAt,
      refreshExpiresAt,
    };
  }

  async revokeSession(sessionId: string, reason: string, now: Date): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session === undefined || session.revokedAt !== null) return;

    session.revokedAt = now;
    session.revokedReason = reason;
    this.revokedSessions.push({ sessionId, reason });

    for (const token of this.refreshTokens.values()) {
      if (token.sessionId === sessionId) token.revokedAt = now;
    }
  }

  async revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void> {
    for (const session of [...this.sessions.values()]) {
      if (session.userId === userId) await this.revokeSession(session.id, reason, now);
    }
  }

  async revokeSessionByRefreshTokenHash(
    tokenHash: string,
    reason: string,
    now: Date,
  ): Promise<string | null> {
    const token = this.refreshTokens.get(tokenHash);
    const session = token === undefined ? undefined : this.sessions.get(token.sessionId);

    if (session === undefined) return null;

    await this.revokeSession(session.id, reason, now);

    return session.userId;
  }

  async isSessionActive(sessionId: string, userId: string, now: Date): Promise<boolean> {
    const session = this.sessions.get(sessionId);

    return (
      session !== undefined &&
      session.userId === userId &&
      session.revokedAt === null &&
      session.expiresAt.getTime() > now.getTime()
    );
  }

  /** Test helper: seeds a user without creating a session. */
  seedUser(user: { id?: string; phone: string; username: string; status?: 'ACTIVE' | 'BLOCKED' }): {
    id: string;
  } {
    const id = user.id ?? randomUUID();

    this.users.set(id, {
      id,
      phone: user.phone,
      username: user.username,
      status: user.status ?? 'ACTIVE',
    });

    return { id };
  }

  private insertSession(input: {
    userId: string;
    deviceKeyHash: string;
    sessionExpiresAt: Date;
  }): FakeSession {
    const session: FakeSession = {
      id: randomUUID(),
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      expiresAt: input.sessionExpiresAt,
      revokedAt: null,
      revokedReason: null,
      lastUsedAt: null,
    };

    this.sessions.set(session.id, session);

    return session;
  }

  private insertRefreshToken(tokenHash: string, sessionId: string, expiresAt: Date): void {
    this.refreshTokens.set(tokenHash, {
      tokenHash,
      sessionId,
      expiresAt,
      usedAt: null,
      revokedAt: null,
    });
  }
}
