/**
 * Persistence boundary for identities and sessions.
 *
 * The auth service owns policy (rotation, revocation, device binding) and only
 * asks this interface for atomic primitives. Two implementations exist: the
 * Prisma one used by the API and an in-memory fake used by the unit tests.
 */

/** DI token so the Prisma implementation can be swapped for the fake. */
export const SESSION_REPOSITORY = Symbol('SESSION_REPOSITORY');

export interface AccountRecord {
  readonly id: string;
  readonly status: 'ACTIVE' | 'BLOCKED';
}

/** Everything a client needs after a session was created or rotated. */
export interface IssuedSessionRecord {
  readonly userId: string;
  readonly sessionId: string;
  readonly deviceKeyHash: string;
  /** False when the caller sent no `X-Device-Key`, so there is nothing to bind. */
  readonly deviceBound: boolean;
  readonly sessionExpiresAt: Date;
  readonly refreshExpiresAt: Date;
}

/** One row of the caller's own device list. Never carries a hash or an IP. */
export interface SessionSummaryRecord {
  readonly id: string;
  readonly deviceLabel: string | null;
  readonly createdAt: Date;
  readonly lastUsedAt: Date;
  readonly expiresAt: Date;
}

export interface CreateAccountInput {
  /** Pre-generated so the device hash can be bound to it up front. */
  readonly userId: string;
  readonly phone: string;
  readonly username: string;
  readonly deviceKeyHash: string;
  readonly deviceBound: boolean;
  readonly deviceLabel: string | null;
  readonly now: Date;
  readonly sessionExpiresAt: Date;
  readonly refreshTokenHash: string;
  readonly refreshExpiresAt: Date;
}

export interface CreateSessionInput {
  readonly userId: string;
  readonly deviceKeyHash: string;
  readonly deviceBound: boolean;
  readonly deviceLabel: string | null;
  readonly now: Date;
  readonly sessionExpiresAt: Date;
  readonly refreshTokenHash: string;
  readonly refreshExpiresAt: Date;
  /** Active sessions allowed per user; the oldest is revoked to make room. */
  readonly maxActiveSessions: number;
}

export interface RotateRefreshTokenInput {
  readonly tokenHash: string;
  readonly nextTokenHash: string;
  readonly now: Date;
  /** Used to cap the next token by the absolute session expiry. */
  readonly refreshTtlMs: number;
}

export interface ChangePhoneInput {
  readonly userId: string;
  /** Already proved by a `phone_change_new` proof; never echoed from a body. */
  readonly phone: string;
  /** Session that asked for the change: the only one left active afterwards. */
  readonly keepSessionId: string | null;
  readonly now: Date;
}

export type ChangePhoneResult =
  | { readonly outcome: 'changed'; readonly revokedSessions: number }
  /** Somebody else owns the number; the unique index decides, not a racy read. */
  | { readonly outcome: 'conflict' }
  /** The account vanished between the proofs and the update. */
  | { readonly outcome: 'not_found' };

export type RotateRefreshTokenResult =
  | {
      readonly outcome: 'rotated';
      readonly userId: string;
      readonly sessionId: string;
      readonly deviceKeyHash: string;
      /** False when the session was created without a device key. */
      readonly deviceBound: boolean;
      /** Checked after rotation: a blocked account must not keep refreshing. */
      readonly userStatus: 'ACTIVE' | 'BLOCKED';
      readonly sessionExpiresAt: Date;
      readonly refreshExpiresAt: Date;
    }
  /** The hash exists and was already spent: the whole user is compromised. */
  | { readonly outcome: 'reused'; readonly userId: string }
  /** Unknown, expired or revoked: indistinguishable to the caller. */
  | { readonly outcome: 'unknown' };

export interface SessionRepository {
  /** Case-insensitive, so `Ivan` cannot shadow `ivan`. */
  isUsernameTaken(username: string): Promise<boolean>;
  findUserByPhone(phoneE164: string): Promise<AccountRecord | null>;
  /** Current phone of one account, or null when the user is gone. */
  findPhoneByUserId(userId: string): Promise<string | null>;
  /** User, device, session and first refresh token in one transaction. */
  createAccount(input: CreateAccountInput): Promise<IssuedSessionRecord | null>;
  createSession(input: CreateSessionInput): Promise<IssuedSessionRecord>;
  /** Single-statement consume + issue; only one caller can win a race. */
  rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult>;
  revokeSession(sessionId: string, reason: string, now: Date): Promise<void>;
  /**
   * Revokes one session that belongs to `userId`. False covers unknown,
   * already revoked and foreign sessions alike, so the caller stays generic.
   */
  revokeUserSession(sessionId: string, userId: string, reason: string, now: Date): Promise<boolean>;
  revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void>;
  /**
   * Moves the account to a new number and revokes every other session of that
   * user in one transaction. `conflict` and `not_found` are both reported as the
   * same generic rejection by the caller.
   */
  changePhone(input: ChangePhoneInput): Promise<ChangePhoneResult>;
  /** Active sessions of one user, most recently used first. */
  listActiveSessions(userId: string, now: Date): Promise<SessionSummaryRecord[]>;
  /** Returns the owning user id, or null when the token is unknown. */
  revokeSessionByRefreshTokenHash(
    tokenHash: string,
    reason: string,
    now: Date,
  ): Promise<string | null>;
  isSessionActive(sessionId: string, userId: string, now: Date): Promise<boolean>;
}
