import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Public } from '../../common/decorators/public.decorator';
import { toErrorResponseBody, type ErrorResponseBody } from '../../common/errors/error-response';
import { getRequestId } from '../../common/middleware/request-id.middleware';
import { OtpService, type OtpRequestContext } from './otp.service';

const DEVICE_KEY_HEADER = 'x-device-key';
const MAX_DEVICE_KEY_LENGTH = 256;

export interface OtpStartResponse {
  readonly ok: true;
}

export interface OtpVerifyResponse {
  readonly proof: string;
}

export interface OtpVerifyError {
  readonly error: 'invalid_code';
}

function readDeviceKey(value: string | string[] | undefined): string | null {
  const candidate = Array.isArray(value) ? value[0] : value;

  return typeof candidate === 'string' &&
    candidate.length > 0 &&
    candidate.length <= MAX_DEVICE_KEY_LENGTH
    ? candidate
    : null;
}

function toContext(request: Request): OtpRequestContext {
  return {
    // Already resolved through the trusted-proxy configuration of the app.
    ip: request.ip ?? request.socket.remoteAddress ?? 'unknown',
    deviceKey: readDeviceKey(request.headers[DEVICE_KEY_HEADER]),
    requestId: getRequestId(request),
  };
}

/**
 * Passwordless entry points. Both are public on purpose: they are the only way
 * to obtain a credential, so they carry no session and no cookies yet.
 */
@Controller('auth/otp')
export class OtpController {
  constructor(private readonly otp: OtpService) {}

  @Public()
  @Post('start')
  @HttpCode(HttpStatus.ACCEPTED)
  async start(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<OtpStartResponse | ErrorResponseBody> {
    const result = await this.otp.start(body, toContext(request));

    if (result.outcome === 'throttled') {
      return tooManyRequests(response, request, result.retryAfterSeconds);
    }

    return { ok: true };
  }

  @Public()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verify(
    @Body() body: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<OtpVerifyResponse | OtpVerifyError | ErrorResponseBody> {
    const result = await this.otp.verify(body, toContext(request));

    if (result.outcome === 'throttled') {
      return tooManyRequests(response, request, result.retryAfterSeconds);
    }

    if (result.outcome === 'rejected') {
      response.status(HttpStatus.BAD_REQUEST);
      return { error: 'invalid_code' };
    }

    return { proof: result.proof };
  }
}

/** Same generic envelope as the global filter, plus the retry hint. */
function tooManyRequests(
  response: Response,
  request: Request,
  retryAfterSeconds: number,
): ErrorResponseBody {
  response.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfterSeconds))));
  response.status(HttpStatus.TOO_MANY_REQUESTS);

  return toErrorResponseBody(HttpStatus.TOO_MANY_REQUESTS, getRequestId(request));
}
