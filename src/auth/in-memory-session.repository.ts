import { randomUUID } from 'node:crypto';
import { Role } from './roles';
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

/**
 * In-memory `SessionRepository` for unit tests.
 *
 * It reproduces the two guarantees the real repository provides - uniqueness of
 * phone/username and single-use refresh tokens - with no `await` between the
 * check and the write, which is the in-process equivalent of the row lock.
 */

interface FakeUser {
  readonly id: string;
  phone: string;
  readonly username: string;
  role: Role;
  identityVerifier: boolean;
  status: 'ACTIVE' | 'BLOCKED';
}

interface FakeSession {
  readonly id: string;
  readonly userId: string;
  readonly deviceKeyHash: string;
  readonly deviceBound: boolean;
  readonly deviceLabel: string | null;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
  lastUsedAt: Date;
  stepupAt: Date | null;
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

    return user === undefined ? null : { id: user.id, status: user.status, role: user.role };
  }

  async findPhoneByUserId(userId: string): Promise<string | null> {
    return this.users.get(userId)?.phone ?? null;
  }

  async findUsernameByUserId(userId: string): Promise<string | null> {
    return this.users.get(userId)?.username ?? null;
  }

  async findUserById(userId: string): Promise<AdminUserRecord | null> {
    const user = this.users.get(userId);

    return user === undefined ? null : { id: user.id, role: user.role, status: user.status };
  }

  /** Check and write without an await in between: the in-process row lock. */
  async setStatusIf(
    userId: string,
    expectedStatus: 'ACTIVE' | 'BLOCKED',
    newStatus: 'ACTIVE' | 'BLOCKED',
  ): Promise<boolean> {
    const user = this.users.get(userId);

    if (user === undefined || user.status !== expectedStatus) return false;

    user.status = newStatus;

    return true;
  }

  async setRoleIf(userId: string, expectedRole: Role, newRole: Role): Promise<boolean> {
    const user = this.users.get(userId);

    if (user === undefined || user.role !== expectedRole) return false;

    user.role = newRole;

    return true;
  }

  async createAccount(input: CreateAccountInput): Promise<IssuedSessionRecord | null> {
    const phoneTaken = [...this.users.values()].some((user) => user.phone === input.phone);
    const usernameTaken = await this.isUsernameTaken(input.username);

    if (phoneTaken || usernameTaken) return null;

    this.users.set(input.userId, {
      id: input.userId,
      phone: input.phone,
      username: input.username,
      role: Role.USER,
      identityVerifier: false,
      status: 'ACTIVE',
    });

    const session = this.insertSession({
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      deviceBound: input.deviceBound,
      deviceLabel: input.deviceLabel,
      sessionExpiresAt: input.sessionExpiresAt,
      now: input.now,
    });

    this.insertRefreshToken(input.refreshTokenHash, session.id, input.refreshExpiresAt);

    return {
      userId: input.userId,
      sessionId: session.id,
      deviceKeyHash: input.deviceKeyHash,
      deviceBound: input.deviceBound,
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

    // Same transaction as the insert, so the cap can never be overshot.
    await this.enforceSessionCap(input.userId, input.maxActiveSessions, input.now);

    const session = this.insertSession({
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      deviceBound: input.deviceBound,
      deviceLabel: input.deviceLabel,
      sessionExpiresAt: input.sessionExpiresAt,
      now: input.now,
    });

    this.insertRefreshToken(input.refreshTokenHash, session.id, input.refreshExpiresAt);

    return {
      userId: input.userId,
      sessionId: session.id,
      deviceKeyHash: input.deviceKeyHash,
      deviceBound: input.deviceBound,
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

    // Captured before the rotation below moves it forward.
    const lastUsedAt = session.lastUsedAt;
    const role = this.users.get(session.userId)?.role ?? Role.USER;

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
      deviceBound: session.deviceBound,
      userStatus: this.users.get(session.userId)?.status ?? 'BLOCKED',
      role,
      lastUsedAt,
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

  async revokeUserSession(
    sessionId: string,
    userId: string,
    reason: string,
    now: Date,
  ): Promise<boolean> {
    const session = this.sessions.get(sessionId);

    // Unknown, already revoked and foreign sessions answer the same way.
    if (session === undefined || session.userId !== userId || session.revokedAt !== null) {
      return false;
    }

    await this.revokeSession(sessionId, reason, now);

    return true;
  }

  async revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void> {
    for (const session of [...this.sessions.values()]) {
      if (session.userId === userId) await this.revokeSession(session.id, reason, now);
    }
  }

  async changePhone(input: ChangePhoneInput): Promise<ChangePhoneResult> {
    const user = this.users.get(input.userId);

    if (user === undefined) return { outcome: 'not_found' };

    // The same rule as the unique index, with no await between check and write.
    const taken = [...this.users.values()].some(
      (candidate) => candidate.id !== user.id && candidate.phone === input.phone,
    );

    if (taken) return { outcome: 'conflict' };

    user.phone = input.phone;

    const others = [...this.sessions.values()].filter(
      (session) =>
        session.userId === user.id &&
        session.revokedAt === null &&
        session.id !== input.keepSessionId,
    );

    for (const session of others) {
      await this.revokeSession(session.id, 'phone_changed', input.now);
    }

    return { outcome: 'changed', revokedSessions: others.length };
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

  async findActiveSession(
    sessionId: string,
    userId: string,
    now: Date,
  ): Promise<ActiveSessionRecord | null> {
    const session = this.sessions.get(sessionId);

    if (
      session === undefined ||
      session.userId !== userId ||
      session.revokedAt !== null ||
      session.expiresAt.getTime() <= now.getTime()
    ) {
      return null;
    }

    const user = this.users.get(userId);

    if (user === undefined) return null;

    return {
      sessionId: session.id,
      userId: user.id,
      role: user.role,
      identityVerifier: user.identityVerifier,
      status: user.status,
    };
  }

  async getStepUpAt(sessionId: string, userId: string): Promise<Date | null> {
    const session = this.sessions.get(sessionId);

    if (
      session === undefined ||
      session.userId !== userId ||
      session.revokedAt !== null ||
      session.expiresAt.getTime() <= Date.now()
    ) {
      return null;
    }

    return session.stepupAt;
  }

  async markStepUp(sessionId: string, userId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    const now = new Date();

    // Same "active session" rule as findActiveSession, with no await in between.
    if (
      session === undefined ||
      session.userId !== userId ||
      session.revokedAt !== null ||
      session.expiresAt.getTime() <= now.getTime()
    ) {
      return false;
    }

    session.stepupAt = now;

    return true;
  }

  async listActiveSessions(userId: string, now: Date): Promise<SessionSummaryRecord[]> {
    return [...this.sessions.values()]
      .filter(
        (session) =>
          session.userId === userId &&
          session.revokedAt === null &&
          session.expiresAt.getTime() > now.getTime(),
      )
      .sort((a, b) => b.lastUsedAt.getTime() - a.lastUsedAt.getTime())
      .map((session) => ({
        id: session.id,
        deviceLabel: session.deviceLabel,
        createdAt: session.createdAt,
        lastUsedAt: session.lastUsedAt,
        expiresAt: session.expiresAt,
      }));
  }

  /** Test helper: seeds a user without creating a session. */
  seedUser(user: {
    id?: string;
    phone: string;
    username: string;
    role?: Role;
    identityVerifier?: boolean;
    status?: 'ACTIVE' | 'BLOCKED';
  }): {
    id: string;
  } {
    const id = user.id ?? randomUUID();

    this.users.set(id, {
      id,
      phone: user.phone,
      username: user.username,
      role: user.role ?? Role.USER,
      identityVerifier: user.identityVerifier ?? false,
      status: user.status ?? 'ACTIVE',
    });

    return { id };
  }

  /**
   * Test helper: changes the stored access level the way an admin would, so a
   * spec can prove the next request already sees the new role.
   */
  setUserRole(
    userId: string,
    access: { readonly role?: Role; readonly identityVerifier?: boolean },
  ): void {
    const user = this.users.get(userId);

    if (user === undefined) throw new Error(`unknown user ${userId}`);

    if (access.role !== undefined) user.role = access.role;
    if (access.identityVerifier !== undefined) user.identityVerifier = access.identityVerifier;
  }

  private insertSession(input: {
    userId: string;
    deviceKeyHash: string;
    deviceBound: boolean;
    deviceLabel: string | null;
    sessionExpiresAt: Date;
    now: Date;
  }): FakeSession {
    const session: FakeSession = {
      id: randomUUID(),
      userId: input.userId,
      deviceKeyHash: input.deviceKeyHash,
      deviceBound: input.deviceBound,
      deviceLabel: input.deviceLabel,
      createdAt: input.now,
      expiresAt: input.sessionExpiresAt,
      revokedAt: null,
      revokedReason: null,
      lastUsedAt: input.now,
      stepupAt: null,
    };

    this.sessions.set(session.id, session);

    return session;
  }

  /** Oldest first, so the cap drops the sessions the user is least likely to use. */
  private async enforceSessionCap(
    userId: string,
    maxActiveSessions: number,
    now: Date,
  ): Promise<void> {
    const active = [...this.sessions.values()]
      .filter(
        (session) =>
          session.userId === userId &&
          session.revokedAt === null &&
          session.expiresAt.getTime() > now.getTime(),
      )
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    const excess = active.length + 1 - maxActiveSessions;

    for (const session of active.slice(0, Math.max(0, excess))) {
      await this.revokeSession(session.id, 'session_cap', now);
    }
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
