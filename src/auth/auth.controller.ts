import {
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { getRequestId } from '../common/middleware/request-id.middleware';
import {
  AuthService,
  type AuthRequestContext,
  type AuthResult,
  type IssuedCredentials,
} from './auth.service';
import { DEVICE_KEY_HEADER, readDeviceKey } from './device-key';
import { OriginCheckGuard } from './guards/origin.guard';
import {
  clearRefreshCookieOptions,
  REFRESH_COOKIE_NAME,
  refreshCookieOptions,
} from './token/refresh-token';

/** What a client sees after register/login/refresh. The cookie is not echoed. */
export interface SessionResponseBody {
  // No user id and no session id: the access token already carries both.
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
}

/** The only two reasons a credential can be refused, in client terms. */
export interface AuthErrorBody {
  readonly error: 'invalid_credentials' | 'unavailable';
}

function toContext(request: Request): AuthRequestContext {
  return {
    // Already resolved through the trusted-proxy configuration of the app.
    ip: request.ip ?? request.socket.remoteAddress ?? 'unknown',
    deviceKey: readDeviceKey(request.headers[DEVICE_KEY_HEADER]),
    requestId: getRequestId(request),
    cookieHeader: request.headers.cookie,
    userAgent: request.headers['user-agent'],
  };
}

function toResponseBody(credentials: IssuedCredentials): SessionResponseBody {
  return {
    accessToken: credentials.accessToken,
    tokenType: credentials.tokenType,
    expiresIn: credentials.expiresIn,
  };
}

/**
 * Collapses a service rejection into 401 ("this credential is not usable") or
 * 409 ("this account cannot be created"). Every other error keeps bubbling up.
 */
function rejectionStatus(error: unknown): 401 | 409 | null {
  if (error instanceof UnauthorizedException || error instanceof ForbiddenException) return 401;
  if (error instanceof ConflictException) return 409;
  return null;
}

function writeRejection(response: Response, status: 401 | 409): AuthErrorBody {
  response.status(status);

  return { error: status === 409 ? 'unavailable' : 'invalid_credentials' };
}

/**
 * Session lifecycle. Every route is `@Public()` because the credential it
 * accepts is the body/cookie itself, not a `Bearer` header.
 *
 * `OriginCheckGuard` is attached at the controller level: these requests carry
 * (or set) an ambient cookie, which is exactly what CSRF needs.
 */
@Controller('auth')
@UseGuards(OriginCheckGuard)
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.OK)
  async register(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionResponseBody | AuthErrorBody | ErrorResponseBody> {
    let result: AuthResult;

    try {
      result = await this.auth.register(body, toContext(request));
    } catch (error) {
      const status = rejectionStatus(error);

      if (status === null) throw error;

      return writeRejection(response, status);
    }

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    return this.attachRefreshCookie(response, result.credentials);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionResponseBody | AuthErrorBody | ErrorResponseBody> {
    let result: AuthResult;

    try {
      result = await this.auth.login(body, toContext(request));
    } catch (error) {
      // An unknown number, a blocked account and a stale proof look the same.
      if (rejectionStatus(error) === null) throw error;

      return writeRejection(response, 401);
    }

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    return this.attachRefreshCookie(response, result.credentials);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionResponseBody | AuthErrorBody | ErrorResponseBody> {
    let result: AuthResult;

    try {
      result = await this.auth.refresh(toContext(request));
    } catch (error) {
      if (rejectionStatus(error) === null) throw error;

      // A cookie that cannot be rotated is worth nothing; drop it so the client
      // re-authenticates instead of replaying it against the reuse detector.
      response.clearCookie(REFRESH_COOKIE_NAME, clearRefreshCookieOptions());

      return writeRejection(response, 401);
    }

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    return this.attachRefreshCookie(response, result.credentials);
  }

  /** 204 even when there was nothing to revoke: the intent is fulfilled. */
  @Public()
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<ErrorResponseBody | undefined> {
    const result = await this.auth.logout(toContext(request));

    // The cookie is cleared in both cases: a stale one is worth nothing, and it
    // must not keep replaying against the reuse detector.
    response.clearCookie(REFRESH_COOKIE_NAME, clearRefreshCookieOptions());

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    return undefined;
  }

  private attachRefreshCookie(
    response: Response,
    credentials: IssuedCredentials,
  ): SessionResponseBody {
    response.cookie(
      REFRESH_COOKIE_NAME,
      credentials.refreshToken,
      refreshCookieOptions(credentials.refreshMaxAgeSeconds),
    );

    return toResponseBody(credentials);
  }
}
