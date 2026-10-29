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
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';
import { verifyAccessToken } from '../token/access-token';

/**
 * Default-deny guard: every route requires authentication unless it is
 * explicitly marked with `@Public()`.
 *
 * A request is authenticated only when all three hold, in this order:
 *
 * 1. the `Authorization` header carries a `Bearer` token,
 * 2. the token verifies (HS256, issuer, audience, not expired),
 * 3. the session named by `sid` still exists, belongs to `sub` and is neither
 *    revoked nor past its absolute expiry.
 *
 * Step 3 costs one indexed lookup per request, which is what makes logout,
 * rotation and reuse detection take effect immediately instead of after the
 * access token expires.
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

    const active = await this.sessions.isSessionActive(claims.sid, claims.sub, new Date());

    if (!active) {
      throw new UnauthorizedException();
    }

    request.auth = {
      userId: claims.sub,
      sessionId: claims.sid,
      expiresAtSeconds: claims.exp,
    };

    return true;
  }

  private nowSeconds(): number {
    return Math.floor(Date.now() / 1_000);
  }
}
