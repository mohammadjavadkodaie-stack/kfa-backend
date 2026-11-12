import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import { writeTooManyRequests, type ErrorResponseBody } from '../../common/errors/error-response';
import { getRequestId } from '../../common/middleware/request-id.middleware';
import type { AuthResult } from '../auth.service';
import { DEVICE_KEY_HEADER, readDeviceKey } from '../device-key';
import { EmailCodeService } from '../email/email-code.service';
import { normalizeEmail } from '../email/email';
import { OriginCheckGuard } from '../guards/origin.guard';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';
import { REFRESH_COOKIE_NAME, refreshCookieOptions } from '../token/refresh-token';
import { EmailAuthService } from './email-auth.service';
import {
  emailSignInSchema,
  emailSignUpSchema,
  emailStartSchema,
  emailVerifySchema,
  parseEmailBody,
} from './email-auth.schema';

interface SessionResponseBody {
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
}

function requestContext(request: Request) {
  return {
    ip: request.ip ?? request.socket.remoteAddress ?? 'unknown',
    deviceKey: readDeviceKey(request.headers[DEVICE_KEY_HEADER]),
    requestId: getRequestId(request),
    cookieHeader: request.headers.cookie,
    userAgent: request.headers['user-agent'],
  };
}

function responseBody(response: Response, result: AuthResult): SessionResponseBody {
  if (result.outcome !== 'issued') throw new Error('expected issued credentials');
  response.cookie(
    REFRESH_COOKIE_NAME,
    result.credentials.refreshToken,
    refreshCookieOptions(result.credentials.refreshMaxAgeSeconds),
  );
  return {
    accessToken: result.credentials.accessToken,
    tokenType: result.credentials.tokenType,
    expiresIn: result.credentials.expiresIn,
  };
}

function serviceResponse(error: unknown): Record<string, unknown> {
  if (!(error instanceof HttpException)) return {};
  const value = error.getResponse();
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function mapThrottle(
  error: unknown,
  request: Request,
  response: Response,
): ErrorResponseBody | null {
  if (!(error instanceof HttpException) || error.getStatus() !== HttpStatus.TOO_MANY_REQUESTS)
    return null;
  const payload = serviceResponse(error);
  const retry = typeof payload.retryAfterSeconds === 'number' ? payload.retryAfterSeconds : 1;
  return writeTooManyRequests(response, request, retry);
}

@Controller('auth')
@UseGuards(OriginCheckGuard)
export class EmailAuthController {
  constructor(
    private readonly emailCode: EmailCodeService,
    private readonly emailAuth: EmailAuthService,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
  ) {}

  @Public()
  @Post('email/start')
  @HttpCode(HttpStatus.ACCEPTED)
  async start(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<{ ok: true } | ErrorResponseBody> {
    const input = parseEmailBody(emailStartSchema, body);
    if (input === null) throw new BadRequestException();
    const email = normalizeEmail(input.email);
    if (email === null) throw new BadRequestException();
    try {
      await this.emailCode.start({
        ...input,
        ip: requestContext(request).ip,
        deviceKey: requestContext(request).deviceKey,
        eligible: (await this.sessions.findUserByEmail(email)) === null,
      });
      return { ok: true };
    } catch (error) {
      const throttled = mapThrottle(error, request, response);
      if (throttled !== null) return throttled;
      throw error;
    }
  }

  @Public()
  @Post('email/verify')
  @HttpCode(HttpStatus.OK)
  async verify(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<{ proof: string } | { error: 'invalid_code' } | ErrorResponseBody> {
    const input = parseEmailBody(emailVerifySchema, body);
    if (input === null) {
      response.status(HttpStatus.BAD_REQUEST);
      return { error: 'invalid_code' };
    }
    try {
      return await this.emailCode.verify({ ...input, ip: requestContext(request).ip });
    } catch (error) {
      const throttled = mapThrottle(error, request, response);
      if (throttled !== null) return throttled;
      if (error instanceof BadRequestException) {
        response.status(HttpStatus.BAD_REQUEST);
        return { error: 'invalid_code' };
      }
      throw error;
    }
  }

  @Public()
  @Post('signup')
  @HttpCode(HttpStatus.OK)
  async signUp(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionResponseBody | ErrorResponseBody | Record<string, unknown>> {
    const input = parseEmailBody(emailSignUpSchema, body);
    if (input === null) throw new BadRequestException();
    try {
      const result = await this.emailAuth.signUp({ ...input, ...requestContext(request) });
      if (result.outcome === 'throttled')
        return writeTooManyRequests(response, request, result.retryAfterSeconds);
      return responseBody(response, result);
    } catch (error) {
      const throttled = mapThrottle(error, request, response);
      if (throttled !== null) return throttled;
      const payload = serviceResponse(error);
      if (payload.error === 'weak_password') {
        response.status(400);
        return payload;
      }
      if (error instanceof UnauthorizedException) {
        response.status(401);
        return { error: 'invalid_credentials' };
      }
      if (error instanceof ConflictException) {
        response.status(409);
        return { error: 'unavailable' };
      }
      throw error;
    }
  }

  @Public()
  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionResponseBody | ErrorResponseBody | Record<string, unknown>> {
    const input = parseEmailBody(emailSignInSchema, body);
    if (input === null) throw new BadRequestException();
    try {
      const result = await this.emailAuth.signIn({
        ...input,
        proof: input.proof,
        ...requestContext(request),
      });
      if (result.outcome === 'throttled')
        return writeTooManyRequests(response, request, result.retryAfterSeconds);
      return responseBody(response, result);
    } catch (error) {
      const throttled = mapThrottle(error, request, response);
      if (throttled !== null) return throttled;
      const payload = serviceResponse(error);
      if (payload.error === 'device_verification_required' || error instanceof ForbiddenException) {
        response.status(403);
        return { error: 'device_verification_required' };
      }
      if (payload.error === 'invalid_credentials' || error instanceof UnauthorizedException) {
        response.status(401);
        return { error: 'invalid_credentials' };
      }
      throw error;
    }
  }
}
