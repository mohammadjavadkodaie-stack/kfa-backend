import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import { isUuid } from '../common/middleware/request-id.middleware';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import { loginSchema, parseAuthBody, registerSchema } from './auth.schema';
import { ephemeralDeviceKey, hashDeviceKey } from './device-key';
import { maskPhone } from './phone';
import { ProofTokenService, type ProofPurpose } from './otp/proof-token';
import {
  generateRefreshToken,
  hashRefreshToken,
  isRefreshTokenShaped,
  readCookie,
  REFRESH_COOKIE_NAME,
  refreshCookieLifetimeSeconds,
} from './token/refresh-token';
import { signAccessToken } from './token/access-token';
import {
  SESSION_REPOSITORY,
  type IssuedSessionRecord,
  type SessionRepository,
} from './session.repository';

/**
 * Registration, login and rotating refresh sessions.
 *
 * Every state change is driven by a credential the caller must already hold:
 * an OTP proof (single use, phone-bound) or a refresh cookie (single use,
 * session-bound). Nothing here trusts a client-supplied id.
 */

export const REGISTER_IP_LIMIT = { limit: 10, windowSeconds: 3_600 } as const;
export const LOGIN_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
export const LOGIN_DEVICE_LIMIT = { limit: 10, windowSeconds: 900 } as const;
export const REFRESH_IP_LIMIT = { limit: 60, windowSeconds: 300 } as const;
export const LOGOUT_IP_LIMIT = { limit: 30, windowSeconds: 300 } as const;
/** Shared per-user budget for listing and revoking sessions. */
export const SESSIONS_USER_LIMIT = { limit: 30, windowSeconds: 60 } as const;

const SESSIONS_USER_SCOPE = 'sessions-user';
const SECONDS_PER_DAY = 86_400;
const MAX_DEVICE_LABEL_LENGTH = 100;

export interface AuthRequestContext {
  readonly ip: string;
  readonly deviceKey: string | null;
  readonly requestId: string;
  /** Raw `Cookie` header; read by hand because there is no cookie parser. */
  readonly cookieHeader: string | undefined;
  /** Raw `User-Agent`, stored only as a short label. */
  readonly userAgent: string | undefined;
}

/** What the client gets on register/login/refresh. */
export interface IssuedCredentials {
  readonly userId: string;
  readonly sessionId: string;
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  /** Access-token lifetime in seconds. */
  readonly expiresIn: number;
  readonly expiresAt: string;
  /** Set as the `__Host-kfa_rt` cookie; never put in the JSON body. */
  readonly refreshToken: string;
  readonly refreshMaxAgeSeconds: number;
}

export type AuthResult =
  | { readonly outcome: 'issued'; readonly credentials: IssuedCredentials }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type LogoutResult =
  | { readonly outcome: 'ok' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

/** The caller behind the access token; never taken from a body or a query. */
export interface SessionPrincipal {
  readonly userId: string;
  readonly sessionId: string;
}

/** One entry of the caller's device list. No hashes, no IPs. */
export interface SessionSummary {
  readonly id: string;
  readonly deviceLabel: string | null;
  readonly createdAt: string;
  readonly lastUsedAt: string;
  readonly expiresAt: string;
  /** True for the session the access token was issued for. */
  readonly current: boolean;
}

export type ListSessionsResult =
  | { readonly outcome: 'ok'; readonly sessions: SessionSummary[] }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type RevokeSessionResult =
  | { readonly outcome: 'revoked'; readonly current: boolean }
  /** Unknown, already revoked and foreign sessions answer the same way. */
  | { readonly outcome: 'not_found' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

export type LogoutAllResult =
  | { readonly outcome: 'ok' }
  | { readonly outcome: 'throttled'; readonly retryAfterSeconds: number };

@Injectable()
export class AuthService {
  private readonly accessTokenSecret: string | undefined;
  private readonly accessTokenTtlSeconds: number;
  private readonly refreshTtlSeconds: number;
  private readonly sessionTtlSeconds: number;
  private readonly maxSessionsPerUser: number;

  constructor(
    @Inject(ENV)
    env: Pick<
      Env,
      | 'ACCESS_TOKEN_SECRET'
      | 'ACCESS_TOKEN_TTL_SECONDS'
      | 'REFRESH_TTL_DAYS'
      | 'SESSION_ABSOLUTE_DAYS'
      | 'SESSIONS_MAX_PER_USER'
    >,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    private readonly proof: ProofTokenService,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.accessTokenSecret = env.ACCESS_TOKEN_SECRET;
    this.accessTokenTtlSeconds = env.ACCESS_TOKEN_TTL_SECONDS;
    this.refreshTtlSeconds = env.REFRESH_TTL_DAYS * SECONDS_PER_DAY;
    this.sessionTtlSeconds = env.SESSION_ABSOLUTE_DAYS * SECONDS_PER_DAY;
    this.maxSessionsPerUser = env.SESSIONS_MAX_PER_USER;
  }

  /**
   * Creates the account and its first session in one transaction.
   *
   * The IP budget is consumed before the proof is touched: an unauthenticated
   * flood must not be able to burn proofs or database connections.
   */
  async register(body: unknown, context: AuthRequestContext): Promise<AuthResult> {
    const registerThrottle = await this.enforceLimit('register-ip', context.ip, REGISTER_IP_LIMIT);

    if (registerThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: registerThrottle };
    }

    const input = parseAuthBody(registerSchema, body);

    if (input === null) {
      throw new BadRequestException();
    }

    // Checked before the proof is consumed: a taken username must not burn the
    // caller's OTP code. The insert still re-checks under its unique index.
    if (await this.sessions.isUsernameTaken(input.username)) {
      throw new ConflictException();
    }

    const phoneE164 = await this.consumeProof(input.proof, 'register');

    if (await this.sessions.findUserByPhone(phoneE164)) {
      // The caller already proved they own the number, so telling them that an
      // account exists reveals nothing they could not discover by logging in.
      throw new ConflictException();
    }

    const now = this.now();
    const userId = randomUUID();
    const refreshToken = generateRefreshToken();
    const sessionExpiresAt = this.sessionExpiry(now);
    const refreshExpiresAt = this.refreshExpiry(now, sessionExpiresAt);

    const created = await this.sessions.createAccount({
      userId,
      phone: phoneE164,
      username: input.username,
      deviceKeyHash: this.deviceBinding(userId, context),
      deviceBound: context.deviceKey !== null,
      deviceLabel: input.deviceName ?? this.deviceLabel(context.userAgent),
      now,
      sessionExpiresAt,
      refreshTokenHash: hashRefreshToken(refreshToken),
      refreshExpiresAt,
    });

    if (created === null) {
      // Lost the race against a concurrent registration for the same phone/username.
      throw new ConflictException();
    }

    await this.writeAudit('auth.registered', created.userId, phoneE164, context, {
      username: input.username,
    });

    this.logger.info(
      { requestId: context.requestId, userId: created.userId, phone: maskPhone(phoneE164) },
      'account registered',
    );

    return {
      outcome: 'issued',
      credentials: this.issueCredentials(created, refreshToken, now),
    };
  }

  /**
   * Issues a new session for an existing, active account.
   *
   * Every failure past the IP check answers 401: whether the proof was stale,
   * the number unknown or the account blocked must look the same from outside.
   */
  async login(body: unknown, context: AuthRequestContext): Promise<AuthResult> {
    const ipThrottle = await this.enforceLimit('login-ip', context.ip, LOGIN_IP_LIMIT);

    if (ipThrottle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: ipThrottle };
    }

    if (context.deviceKey !== null) {
      // A shared device budget, HMAC'd by the rate-limit service before storage.
      const deviceThrottle = await this.enforceLimit(
        'login-device',
        context.deviceKey,
        LOGIN_DEVICE_LIMIT,
      );

      if (deviceThrottle !== null) {
        return { outcome: 'throttled', retryAfterSeconds: deviceThrottle };
      }
    }

    const input = parseAuthBody(loginSchema, body);

    if (input === null) {
      throw new BadRequestException();
    }

    const phoneE164 = await this.consumeProof(input.proof, 'login');
    const account = await this.sessions.findUserByPhone(phoneE164);

    if (account === null) {
      // Same generic rejection as a bad proof: registration cannot be probed.
      throw new UnauthorizedException();
    }

    if (account.status !== 'ACTIVE') {
      await this.writeAudit('auth.login.blocked', account.id, phoneE164, context, {});
      throw new ForbiddenException();
    }

    const now = this.now();
    const refreshToken = generateRefreshToken();
    const sessionExpiresAt = this.sessionExpiry(now);
    const refreshExpiresAt = this.refreshExpiry(now, sessionExpiresAt);

    const session = await this.sessions.createSession({
      userId: account.id,
      deviceKeyHash: this.deviceBinding(account.id, context),
      deviceBound: context.deviceKey !== null,
      deviceLabel: this.deviceLabel(context.userAgent),
      now,
      sessionExpiresAt,
      refreshTokenHash: hashRefreshToken(refreshToken),
      refreshExpiresAt,
      maxActiveSessions: this.maxSessionsPerUser,
    });

    await this.writeAudit('auth.login', account.id, phoneE164, context, {});

    this.logger.info(
      { requestId: context.requestId, userId: account.id, phone: maskPhone(phoneE164) },
      'login succeeded',
    );

    return {
      outcome: 'issued',
      credentials: this.issueCredentials(session, refreshToken, now),
    };
  }

  /**
   * Rotates the refresh token and mints a new access token.
   *
   * A token that was already spent means two parties hold the cookie, so the
   * whole user is logged out: the legitimate client re-authenticates with an
   * OTP, the thief is left with nothing.
   */
  async refresh(context: AuthRequestContext): Promise<AuthResult> {
    const throttle = await this.enforceLimit('refresh-ip', context.ip, REFRESH_IP_LIMIT);

    if (throttle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: throttle };
    }

    const token = readCookie(context.cookieHeader, REFRESH_COOKIE_NAME);

    if (!isRefreshTokenShaped(token)) {
      throw new UnauthorizedException();
    }

    const now = this.now();
    const nextToken = generateRefreshToken();

    const result = await this.sessions.rotateRefreshToken({
      tokenHash: hashRefreshToken(token),
      nextTokenHash: hashRefreshToken(nextToken),
      now,
      refreshTtlMs: this.refreshTtlSeconds * 1_000,
    });

    if (result.outcome === 'reused') {
      await this.sessions.revokeAllUserSessions(result.userId, 'refresh_reuse', now);
      await this.writeAudit('auth.refresh.reused', result.userId, null, context, {});
      this.logger.warn(
        { requestId: context.requestId, userId: result.userId },
        'refresh token reuse detected; all sessions revoked',
      );
      throw new UnauthorizedException();
    }

    if (result.outcome === 'unknown') {
      // Expired, revoked or never existed: the client just re-authenticates.
      throw new UnauthorizedException();
    }

    if (!this.deviceMatches(result, context)) {
      await this.sessions.revokeSession(result.sessionId, 'device_mismatch', now);
      await this.writeAudit('auth.refresh.device_mismatch', result.userId, null, context, {});
      this.logger.warn(
        { requestId: context.requestId, userId: result.userId },
        'refresh rejected: device key does not match the session',
      );
      throw new UnauthorizedException();
    }

    if (result.userStatus !== 'ACTIVE') {
      await this.sessions.revokeSession(result.sessionId, 'account_blocked', now);
      await this.writeAudit('auth.refresh.blocked', result.userId, null, context, {});
      throw new ForbiddenException();
    }

    const credentials = this.issueCredentials(result, nextToken, now);

    return { outcome: 'issued', credentials };
  }

  /**
   * Revokes the session behind the cookie. Always succeeds from the client's
   * point of view: an unknown cookie means the goal is already met.
   */
  async logout(context: AuthRequestContext): Promise<LogoutResult> {
    const throttle = await this.enforceLimit('logout-ip', context.ip, LOGOUT_IP_LIMIT);

    if (throttle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: throttle };
    }

    const token = readCookie(context.cookieHeader, REFRESH_COOKIE_NAME);

    if (!isRefreshTokenShaped(token)) {
      return { outcome: 'ok' };
    }

    const now = this.now();
    const userId = await this.sessions.revokeSessionByRefreshTokenHash(
      hashRefreshToken(token),
      'logout',
      now,
    );

    if (userId !== null) {
      await this.writeAudit('auth.logout', userId, null, context, {});
      this.logger.info({ requestId: context.requestId, userId }, 'session revoked');
    }

    return { outcome: 'ok' };
  }

  /**
   * The caller's own active sessions, most recently used first.
   *
   * No hashed key and no IP: the list exists so a user can recognise (and drop)
   * their devices, not so a stolen token can map the account.
   */
  async listSessions(principal: SessionPrincipal): Promise<ListSessionsResult> {
    const throttle = await this.enforceLimit(
      SESSIONS_USER_SCOPE,
      principal.userId,
      SESSIONS_USER_LIMIT,
    );

    if (throttle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: throttle };
    }

    const records = await this.sessions.listActiveSessions(principal.userId, this.now());

    return {
      outcome: 'ok',
      sessions: records.map((record) => ({
        id: record.id,
        deviceLabel: record.deviceLabel,
        createdAt: record.createdAt.toISOString(),
        lastUsedAt: record.lastUsedAt.toISOString(),
        expiresAt: record.expiresAt.toISOString(),
        current: record.id === principal.sessionId,
      })),
    };
  }

  /**
   * Revokes one of the caller's own sessions.
   *
   * A session owned by somebody else answers exactly like one that never
   * existed, so the id space cannot be enumerated and a caller cannot log a
   * stranger out by guessing ids.
   */
  async revokeSession(
    principal: SessionPrincipal,
    sessionId: string,
    context: AuthRequestContext,
  ): Promise<RevokeSessionResult> {
    const throttle = await this.enforceLimit(
      SESSIONS_USER_SCOPE,
      principal.userId,
      SESSIONS_USER_LIMIT,
    );

    if (throttle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: throttle };
    }

    // A malformed id cannot own a row, and skipping the query keeps garbage free.
    if (!isUuid(sessionId)) return { outcome: 'not_found' };

    const revoked = await this.sessions.revokeUserSession(
      sessionId,
      principal.userId,
      'user_revoked',
      this.now(),
    );

    if (!revoked) return { outcome: 'not_found' };

    const current = sessionId === principal.sessionId;

    await this.writeAudit('auth.session.revoked', principal.userId, null, context, {
      sessionId,
      current,
    });

    this.logger.info(
      { requestId: context.requestId, userId: principal.userId, sessionId, current },
      'session revoked by user',
    );

    return { outcome: 'revoked', current };
  }

  /**
   * Revokes every session of the caller, including the one that asked.
   *
   * The refresh cookie is cleared by the controller, so a client that lost its
   * device re-authenticates with an OTP and nothing else keeps working.
   */
  async logoutAll(
    principal: SessionPrincipal,
    context: AuthRequestContext,
  ): Promise<LogoutAllResult> {
    const throttle = await this.enforceLimit(
      SESSIONS_USER_SCOPE,
      principal.userId,
      SESSIONS_USER_LIMIT,
    );

    if (throttle !== null) {
      return { outcome: 'throttled', retryAfterSeconds: throttle };
    }

    await this.sessions.revokeAllUserSessions(principal.userId, 'logout_all', this.now());
    await this.writeAudit('auth.logout_all', principal.userId, null, context, {});

    this.logger.info(
      { requestId: context.requestId, userId: principal.userId },
      'all sessions revoked',
    );

    return { outcome: 'ok' };
  }

  /** Returns the retry hint when the budget is exhausted, or null when allowed. */
  private async enforceLimit(
    scope: string,
    identifier: string,
    limit: { limit: number; windowSeconds: number },
  ): Promise<number | null> {
    const decision = await this.rateLimit.consume({ scope, identifier, ...limit });

    return decision.allowed ? null : decision.retryAfterSeconds;
  }

  /**
   * The proof is consumed even when the caller is then rejected, but only for
   * the purpose this endpoint exists for: a proof minted elsewhere is refused.
   */
  private async consumeProof(proof: unknown, purpose: ProofPurpose): Promise<string> {
    const phoneE164 = await this.proof.verifyAndConsumeProof(proof, purpose);

    if (phoneE164 === null) {
      throw new UnauthorizedException();
    }

    return phoneE164;
  }

  /** Absolute cap: rotation can approach it but never pass it. */
  private sessionExpiry(now: Date): Date {
    return new Date(now.getTime() + this.sessionTtlSeconds * 1_000);
  }

  private refreshExpiry(now: Date, sessionExpiresAt: Date): Date {
    return new Date(
      Math.min(now.getTime() + this.refreshTtlSeconds * 1_000, sessionExpiresAt.getTime()),
    );
  }

  /**
   * Binds the session to the hashed `X-Device-Key`. Without that header the
   * binding is a fresh random value, so the cookie stays the only credential
   * (which is the documented behaviour of clients that send no key).
   */
  private deviceBinding(userId: string, context: AuthRequestContext): string {
    const raw = context.deviceKey ?? ephemeralDeviceKey();

    return hashDeviceKey(this.secretOrFail(), userId, raw);
  }

  private deviceMatches(
    session: {
      readonly userId: string;
      readonly deviceKeyHash: string;
      readonly deviceBound: boolean;
    },
    context: AuthRequestContext,
  ): boolean {
    // A session created without a key has nothing to compare against; the
    // cookie is its only credential, so any client holding it may rotate.
    if (!session.deviceBound) return true;

    // The reverse direction must be strict: a bound session refreshed without
    // the header would turn the binding into an opt-in an attacker can skip.
    if (context.deviceKey === null) return false;

    return (
      hashDeviceKey(this.secretOrFail(), session.userId, context.deviceKey) ===
      session.deviceKeyHash
    );
  }

  /** `User-Agent` is truncated, never stored raw: it is only a UI label. */
  private deviceLabel(userAgent: string | undefined): string | null {
    if (typeof userAgent !== 'string') return null;

    const label = userAgent.trim().slice(0, MAX_DEVICE_LABEL_LENGTH);

    return label.length > 0 ? label : null;
  }

  private issueCredentials(
    session: IssuedSessionRecord,
    refreshToken: string,
    now: Date,
  ): IssuedCredentials {
    const accessToken = signAccessToken({
      secret: this.secretOrFail(),
      userId: session.userId,
      sessionId: session.sessionId,
      issuedAtSeconds: Math.floor(now.getTime() / 1_000),
      ttlSeconds: this.accessTokenTtlSeconds,
    });

    return {
      userId: session.userId,
      sessionId: session.sessionId,
      accessToken,
      tokenType: 'Bearer',
      expiresIn: this.accessTokenTtlSeconds,
      expiresAt: new Date(now.getTime() + this.accessTokenTtlSeconds * 1_000).toISOString(),
      refreshToken,
      refreshMaxAgeSeconds: refreshCookieLifetimeSeconds(
        this.refreshTtlSeconds,
        session.sessionExpiresAt,
        now,
      ),
    };
  }

  /** Fail closed: without the signing secret no session can be issued. */
  private secretOrFail(): string {
    const secret = this.accessTokenSecret;

    if (secret === undefined) {
      throw new ServiceUnavailableException();
    }

    return secret;
  }

  private now(): Date {
    return new Date();
  }

  /**
   * Best effort: an audit outage must never let a login succeed silently, so the
   * failure is logged at warn level and the flow continues (the session itself
   * is the record). Security-relevant hits also bump the warning log.
   */
  private async writeAudit(
    action: string,
    actorId: string,
    phoneE164: string | null,
    context: AuthRequestContext,
    extra: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorId,
        actorRole: 'user',
        targetType: 'session',
        targetId: actorId,
        requestId: context.requestId,
        ip: context.ip,
        metadata: {
          actor: 'user',
          ...(phoneE164 === null ? {} : { phone: maskPhone(phoneE164) }),
          ...extra,
        },
      });
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'auth audit failed');
    }
  }
}
