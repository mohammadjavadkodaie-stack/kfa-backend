import {
  Catch,
  HttpException,
  HttpStatus,
  Injectable,
  type ArgumentsHost,
  type ExceptionFilter,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { PinoLogger } from 'nestjs-pino';
import { toErrorResponseBody, readPublicErrorCode } from '../errors/error-response';
import { getRequestId } from '../middleware/request-id.middleware';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isValidStatus(value: number): boolean {
  return Number.isInteger(value) && value >= 400 && value <= 599;
}

/**
 * Resolves the client-facing status code without ever trusting an error
 * message. Unknown failures are always reported as 500.
 */
export function resolveStatusCode(exception: unknown): number {
  if (exception instanceof HttpException) {
    const status = exception.getStatus();
    return isValidStatus(status) ? status : HttpStatus.INTERNAL_SERVER_ERROR;
  }

  // `http-errors` instances (body parser, cors, ...) are 4xx and explicitly
  // marked as safe to expose - only the status code is reused, never the text.
  if (isRecord(exception) && exception.expose === true) {
    const rawStatus =
      typeof exception.status === 'number' ? exception.status : exception.statusCode;

    if (typeof rawStatus === 'number' && isValidStatus(rawStatus) && rawStatus < 500) {
      return rawStatus;
    }
  }

  return HttpStatus.INTERNAL_SERVER_ERROR;
}

/**
 * Last line of defence: converts every exception into the generic JSON error
 * envelope and logs the real error server-side.
 */
@Injectable()
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly logger: PinoLogger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const response = context.getResponse<Response>();
    const request = context.getRequest<Request>();

    const requestId = getRequestId(request);
    const statusCode = resolveStatusCode(exception);
    const path = (request.originalUrl || request.url || '').split('?')[0];

    const logPayload = {
      err: exception,
      requestId,
      statusCode,
      method: request.method,
      path,
    };

    if (statusCode >= HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(logPayload, 'request failed');
    } else {
      this.logger.warn(logPayload, 'request rejected');
    }

    if (response.headersSent) {
      return;
    }

    response
      .status(statusCode)
      .json(toErrorResponseBody(statusCode, requestId, readPublicErrorCode(exception)));
  }
}
