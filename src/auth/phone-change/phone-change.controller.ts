import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { writeTooManyRequests, type ErrorResponseBody } from '../../common/errors/error-response';
import { getRequestId } from '../../common/middleware/request-id.middleware';
import type { AuthRequestContext, SessionPrincipal } from '../auth.service';
import { DEVICE_KEY_HEADER, readDeviceKey } from '../device-key';
import type { AuthenticatedRequest } from '../guards/auth.guard';
import { OriginCheckGuard } from '../guards/origin.guard';
import { PhoneChangeService } from './phone-change.service';

/** `POST /auth/phone-change/start`: accepted, never "sent to X". */
export interface PhoneChangeStartResponse {
  readonly ok: true;
}

/** `verify-new` / `verify-old`: one single-use proof for the confirm step. */
export interface PhoneChangeProofResponse {
  readonly proof: string;
}

export interface PhoneChangeError {
  readonly error: 'invalid_code' | 'phone_change_rejected';
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

/** The global guard already rejected anything without a trusted principal. */
function requirePrincipal(request: AuthenticatedRequest): SessionPrincipal {
  const auth = request.auth;

  if (auth === undefined) throw new UnauthorizedException();

  return { userId: auth.userId, sessionId: auth.sessionId };
}

/**
 * Changing the number on an account without the old one: requires the access
 * token on every route, so the current number always comes from the session
 * owner rather than from a body.
 *
 * `OriginCheckGuard` is attached because the refresh cookie rides along with
 * these state-changing requests.
 */
@Controller('auth/phone-change')
@UseGuards(OriginCheckGuard)
export class PhoneChangeController {
  constructor(private readonly phoneChange: PhoneChangeService) {}

  @Post('start')
  @HttpCode(HttpStatus.ACCEPTED)
  async start(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PhoneChangeStartResponse | ErrorResponseBody> {
    const result = await this.phoneChange.start(
      requirePrincipal(request),
      body,
      toContext(request),
    );

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    return { ok: true };
  }

  @Post('verify-new')
  @HttpCode(HttpStatus.OK)
  async verifyNew(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PhoneChangeProofResponse | PhoneChangeError | ErrorResponseBody> {
    const result = await this.phoneChange.verifyNew(
      requirePrincipal(request),
      body,
      toContext(request),
    );

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    if (result.outcome === 'rejected') {
      response.status(HttpStatus.BAD_REQUEST);
      return { error: 'invalid_code' };
    }

    return { proof: result.proof };
  }

  @Post('verify-old')
  @HttpCode(HttpStatus.OK)
  async verifyOld(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PhoneChangeProofResponse | PhoneChangeError | ErrorResponseBody> {
    const result = await this.phoneChange.verifyOld(
      requirePrincipal(request),
      body,
      toContext(request),
    );

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    if (result.outcome === 'rejected') {
      response.status(HttpStatus.BAD_REQUEST);
      return { error: 'invalid_code' };
    }

    return { proof: result.proof };
  }

  /**
   * 204 on success: the change is the answer, and the session that asked keeps
   * working. Every failure is the same 400, so a taken number cannot be told
   * apart from an expired proof.
   */
  @Post('confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  async confirm(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<PhoneChangeError | ErrorResponseBody | undefined> {
    const result = await this.phoneChange.confirm(
      requirePrincipal(request),
      body,
      toContext(request),
    );

    if (result.outcome === 'throttled') {
      return writeTooManyRequests(response, request, result.retryAfterSeconds);
    }

    if (result.outcome === 'rejected') {
      response.status(HttpStatus.BAD_REQUEST);
      return { error: 'phone_change_rejected' };
    }

    return undefined;
  }
}
