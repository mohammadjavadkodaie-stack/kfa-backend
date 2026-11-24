/**
 * Persistence boundary for identities and sessions.
 *
 * The auth service owns policy (rotation, revocation, device binding) and only
 * asks this interface for atomic primitives. Two implementations exist: the
 * Prisma one used by the API and an in-memory fake used by the unit tests.
 */

import type { Prisma } from '@prisma/client';
import type { Role } from './roles';

/** DI token so the Prisma implementation can be swapped for the fake. */
export const SESSION_REPOSITORY = Symbol('SESSION_REPOSITORY');

export interface AccountRecord {
  readonly id: string;
  readonly status: 'ACTIVE' | 'BLOCKED';
  /** Read at login: a staff session gets the shorter absolute lifetime. */
  readonly role: Role;
}

export interface EmailAccountRecord extends AccountRecord {
  readonly username: string;
  readonly passwordHash: string | null;
  readonly emailVerifiedAt: Date | null;
}

/** What the admin module may read about a target; it carries no contact data. */
export interface AdminUserRecord {
  readonly id: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'BLOCKED';
}

/** Already validated: the service applies the defaults before the store sees it. */
export interface AdminUserListQuery {
  readonly page: number;
  readonly pageSize: number;
  readonly role?: Role;
  /** True keeps only the blocked accounts, false only the active ones. */
  readonly blocked?: boolean;
  /** Normalised before it reaches the store, and matched exactly. */
  readonly email?: string;
}

/**
 * One row of `GET /admin/users`. The allowlist is the point: the page is meant
 * for a human scanning accounts, so it carries the name, the address and the
 * access facts - never a password hash, a phone number or a second-factor state.
 */
export interface AdminUserListRecord {
  readonly id: string;
  readonly username: string;
  readonly email: string | null;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'BLOCKED';
  readonly createdAt: Date;
}

export interface AdminUserListPage {
  readonly rows: readonly AdminUserListRecord[];
  /** Rows matching the filter before the page cut; the caller needs it to page. */
  readonly total: number;
}

/**
 * What the guard needs from one live session.
 *
 * The role and the verifier flag are read together with the session so a change
 * made in the database applies on the very next request without a second query.
 */
export interface ActiveSessionRecord {
  readonly sessionId: string;
  readonly userId: string;
  /** Current role from the database; never taken from the access token. */
  readonly role: Role;
  /** Separate permission, independent of `role`. */
  readonly identityVerifier: boolean;
  readonly status: 'ACTIVE' | 'BLOCKED';
}

/**
 * What the caller may learn about its own account at boot.
 *
 * Deliberately four fields: no phone, no id, no timestamps and no flags beyond
 * the one the UI needs to decide whether to send the user to the profile form.
 */
export interface SelfProfileRecord {
  readonly username: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'BLOCKED';
  readonly hasAthleteProfile: boolean;
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
  readonly phone: string | null;
  readonly email?: string;
  readonly passwordHash?: string;
  readonly emailVerifiedAt?: Date;
  readonly username: string;
  readonly deviceKeyHash: string;
  readonly deviceBound: boolean;
  readonly deviceLabel: string | null;
  readonly now: Date;
  readonly sessionExpiresAt: Date;
  readonly refreshTokenHash: string;
  readonly refreshExpiresAt: Date;
}

export type CreateEmailAccountInput = CreateAccountInput & {
  readonly email: string;
  readonly passwordHash: string;
  readonly emailVerifiedAt: Date;
};

export type CreateEmailAccountResult = IssuedSessionRecord | { readonly outcome: 'conflict' };

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
      /** Current role, so the caller can apply the staff idle limit. */
      readonly role: Role;
      /** Last activity of the session (creation or previous rotation). */
      readonly lastUsedAt: Date;
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
  findUserByEmail(email: string): Promise<EmailAccountRecord | null>;
  updatePasswordHash(userId: string, hash: string): Promise<void>;
  isKnownDevice(userId: string, deviceKeyHash: string): Promise<boolean>;
  /** Username of one account. Used as the TOTP label. */
  findUsernameByUserId(userId: string): Promise<string | null>;
  /** Administrative view of one account, or null when the id owns no row. */
  findUserById(userId: string): Promise<AdminUserRecord | null>;
  /**
   * One page of accounts, oldest first. Filters are applied inside the store,
   * so a page is a slice of the filtered set, never of an unfiltered read.
   */
  listAccounts(query: AdminUserListQuery): Promise<AdminUserListPage>;
  /**
   * Self-description behind `GET /auth/me`, or null when the account is gone.
   * One query: the profile flag is decided by the database, not by a second
   * round trip the caller could race.
   */
  findSelfProfile(userId: string): Promise<SelfProfileRecord | null>;
  /**
   * Compare-and-set on the status: one statement with the expected value in the
   * predicate, so two callers holding the same expectation cannot both win.
   *
   * A caller that already owns a transaction passes it as `tx`, so the status
   * change commits or rolls back together with the audit row that describes it.
   */
  setStatusIf(
    userId: string,
    expectedStatus: 'ACTIVE' | 'BLOCKED',
    newStatus: 'ACTIVE' | 'BLOCKED',
    tx?: Prisma.TransactionClient,
  ): Promise<boolean>;
  /** Same contract as `setStatusIf`, for the role. */
  setRoleIf(userId: string, expectedRole: Role, newRole: Role): Promise<boolean>;
  /**
   * Number of accounts currently holding `role`. The first-owner bootstrap
   * reads it to refuse its run the moment any OWNER exists.
   */
  countUsersByRole(role: Role): Promise<number>;
  /** User, device, session and first refresh token in one transaction. */
  createAccount(input: CreateAccountInput): Promise<IssuedSessionRecord | null>;
  createAccountWithEmail(input: CreateEmailAccountInput): Promise<CreateEmailAccountResult>;
  createSession(input: CreateSessionInput): Promise<IssuedSessionRecord>;
  /** Single-statement consume + issue; only one caller can win a race. */
  rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult>;
  revokeSession(sessionId: string, reason: string, now: Date): Promise<void>;
  /**
   * Revokes one session that belongs to `userId`. False covers unknown,
   * already revoked and foreign sessions alike, so the caller stays generic:
   * a foreign or unknown id must answer exactly like not found.
   */
  revokeUserSession(sessionId: string, userId: string, reason: string, now: Date): Promise<boolean>;
  revokeAllUserSessions(userId: string, reason: string, now: Date): Promise<void>;
  /**
   * Revokes every live session of `userId` except `keepSessionId`, together with
   * their refresh tokens. Used after a factor rotation: the device that proved
   * the new factor keeps working, every other one must authenticate again.
   */
  revokeOtherUserSessions(
    userId: string,
    keepSessionId: string,
    reason: string,
    now: Date,
  ): Promise<void>;
  /** Active sessions of one user, most recently used first. */
  listActiveSessions(userId: string, now: Date): Promise<SessionSummaryRecord[]>;
  /** Returns the owning user id, or null when the token is unknown. */
  revokeSessionByRefreshTokenHash(
    tokenHash: string,
    reason: string,
    now: Date,
  ): Promise<string | null>;
  /**
   * Single query for the guard: the session must still be live and belong to
   * `userId`, and the owning account is returned with its current role, its
   * identity-verifier flag and its status.
   */
  findActiveSession(
    sessionId: string,
    userId: string,
    now: Date,
  ): Promise<ActiveSessionRecord | null>;
  /**
   * Latest step-up of one live session of `userId`, or null. A foreign,
   * revoked or expired session answers like a session that never stepped up.
   */
  getStepUpAt(sessionId: string, userId: string): Promise<Date | null>;
  /**
   * Single atomic update of one live session of `userId`. True only when that
   * one row changed; unknown, foreign, revoked and expired sessions answer false.
   */
  markStepUp(sessionId: string, userId: string): Promise<boolean>;
}
