import {
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import type { Role } from '../roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';
import { verifyAccessToken } from '../token/access-token';

/**
 * Default-deny guard: every route requires authentication unless it is
 * explicitly marked with `@Public()`.
 *
 * A request is authenticated only when all four hold, in this order:
 *
 * 1. the `Authorization` header carries a `Bearer` token,
 * 2. the token verifies (HS256, issuer, audience, not expired),
 * 3. the session named by `sid` still exists, belongs to `sub` and is neither
 *    revoked nor past its absolute expiry,
 * 4. the account behind that session is still active.
 *
 * Step 3 also returns the caller's role and identity-verifier flag, in the same
 * query, so authorisation decisions never depend on the access token: demoting,
 * promoting or blocking an account applies on the very next request.
 *
 * The lookup costs one indexed query per request, which is what makes logout,
 * rotation, reuse detection and role changes take effect immediately instead of
 * after the access token expires.
 */

/** Parsed `Authorization: Bearer <token>` value. */
export function readBearerToken(header: string | string[] | undefined): string | null {
  const value = Array.isArray(header) ? header[0] : header;

  if (typeof value !== 'string') return null;

  const match = /^Bearer +([^\s]+)$/i.exec(value.trim());

  return match === null ? null : (match[1] ?? null);
}

/** What a downstream handler can trust after the guard ran. */
export interface RequestPrincipal {
  readonly userId: string;
  readonly sessionId: string;
  /** Loaded from the database for this request, never from the token. */
  readonly role: Role;
  /** Separate permission, independent of `role`. */
  readonly identityVerifier: boolean;
  /** Access-token expiry, seconds since the epoch. */
  readonly expiresAtSeconds: number;
}

export type AuthenticatedRequest = Request & { auth?: RequestPrincipal };

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly accessTokenSecret: string | undefined;

  constructor(
    private readonly reflector: Reflector,
    @Inject(ENV) env: Pick<Env, 'ACCESS_TOKEN_SECRET'>,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
  ) {
    // Captured once instead of per request; the env object is frozen.
    this.accessTokenSecret = env.ACCESS_TOKEN_SECRET;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic === true) {
      return true;
    }

    const secret = this.accessTokenSecret;

    // No signing secret means no token can be trusted; refuse rather than
    // treating the request as anonymous-and-allowed.
    if (secret === undefined) {
      throw new UnauthorizedException();
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = readBearerToken(request.headers.authorization);

    if (token === null) {
      throw new UnauthorizedException();
    }

    const claims = verifyAccessToken({ secret, token, nowSeconds: this.nowSeconds() });

    if (claims === null) {
      throw new UnauthorizedException();
    }

    const active = await this.sessions.findActiveSession(claims.sid, claims.sub, new Date());

    // A revoked session and a blocked account look the same from outside: the
    // request is simply not authenticated.
    if (active === null || active.status !== 'ACTIVE') {
      throw new UnauthorizedException();
    }

    request.auth = {
      userId: active.userId,
      sessionId: active.sessionId,
      role: active.role,
      identityVerifier: active.identityVerifier,
      expiresAtSeconds: claims.exp,
    };

    return true;
  }

  private nowSeconds(): number {
    return Math.floor(Date.now() / 1_000);
  }
}
