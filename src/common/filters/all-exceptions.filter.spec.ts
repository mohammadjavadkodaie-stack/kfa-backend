import {
  ForbiddenException,
  HttpException,
  NotFoundException,
  type ArgumentsHost,
} from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { AllExceptionsFilter, resolveStatusCode } from './all-exceptions.filter';

const REQUEST_ID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

interface RequestStub {
  id?: unknown;
  method: string;
  originalUrl: string;
}

function createHost(request: Partial<RequestStub> = {}) {
  const bodies: unknown[] = [];
  const status = jest.fn();
  const json = jest.fn((body: unknown) => {
    bodies.push(body);
  });
  const response = { headersSent: false, status, json };

  status.mockReturnValue(response);

  const req: RequestStub = {
    id: REQUEST_ID,
    method: 'GET',
    originalUrl: '/secret?token=abc',
    ...request,
  };

  const host = {
    switchToHttp: () => ({
      getResponse: () => response,
      getRequest: () => req,
    }),
  } as unknown as ArgumentsHost;

  return { host, response, bodies };
}

function createLogger(): { logger: PinoLogger; error: jest.Mock; warn: jest.Mock } {
  const error = jest.fn();
  const warn = jest.fn();

  return { logger: { error, warn } as unknown as PinoLogger, error, warn };
}

describe('AllExceptionsFilter', () => {
  it('hides internal failure details behind a generic 500', () => {
    const { host, response, bodies } = createHost();
    const { logger, error } = createLogger();

    new AllExceptionsFilter(logger).catch(new Error('db down: password=hunter2'), host);

    expect(response.status).toHaveBeenCalledWith(500);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toEqual({
      statusCode: 500,
      message: 'Internal Server Error',
      requestId: REQUEST_ID,
    });
    expect(JSON.stringify(bodies[0])).not.toContain('stack');
    expect(JSON.stringify(bodies[0])).not.toContain('hunter2');
    expect(JSON.stringify(bodies[0])).not.toContain('token');
    expect(error).toHaveBeenCalledTimes(1);
  });

  it('logs the real error server-side without the query string', () => {
    const { host } = createHost();
    const { logger, error } = createLogger();

    new AllExceptionsFilter(logger).catch(new Error('boom'), host);

    const payload = error.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({ statusCode: 500, requestId: REQUEST_ID, path: '/secret' });
    expect(payload.err).toBeInstanceOf(Error);
  });

  it('keeps framework messages out of the response for 4xx errors', () => {
    const { host, response, bodies } = createHost();
    const { logger, warn } = createLogger();

    new AllExceptionsFilter(logger).catch(new NotFoundException('Cannot GET /secret'), host);

    expect(response.status).toHaveBeenCalledWith(404);
    expect(bodies[0]).toEqual({ statusCode: 404, message: 'Not Found', requestId: REQUEST_ID });
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('falls back to "unknown" when the request has no id', () => {
    const { host, bodies } = createHost({ id: undefined });
    const { logger } = createLogger();

    new AllExceptionsFilter(logger).catch(new Error('boom'), host);

    expect(bodies[0]).toMatchObject({ requestId: 'unknown' });
  });

  it('passes the step-up code through, which is the one actionable refusal', () => {
    const { host, response, bodies } = createHost();
    const { logger } = createLogger();

    new AllExceptionsFilter(logger).catch(
      new ForbiddenException({ code: 'step_up_required' }),
      host,
    );

    expect(response.status).toHaveBeenCalledWith(403);
    expect(bodies[0]).toEqual({
      statusCode: 403,
      message: 'Forbidden',
      requestId: REQUEST_ID,
      code: 'step_up_required',
    });
  });

  it('drops any other code and any message an exception carries', () => {
    const { host, bodies } = createHost();
    const { logger } = createLogger();

    new AllExceptionsFilter(logger).catch(
      new ForbiddenException({ code: 'account_suspended', hint: 'ask an admin' }),
      host,
    );

    expect(bodies[0]).toEqual({ statusCode: 403, message: 'Forbidden', requestId: REQUEST_ID });
    expect(JSON.stringify(bodies[0])).not.toContain('account_suspended');
    expect(JSON.stringify(bodies[0])).not.toContain('ask an admin');
  });

  it('does not write a second response when headers were already sent', () => {
    const { host, response } = createHost();
    const { logger } = createLogger();
    response.headersSent = true;

    new AllExceptionsFilter(logger).catch(new Error('boom'), host);

    expect(response.json).not.toHaveBeenCalled();
  });
});

describe('resolveStatusCode', () => {
  it('keeps framework status codes', () => {
    expect(resolveStatusCode(new NotFoundException())).toBe(404);
  });

  it('maps exposed http-errors (body parser) to their status', () => {
    expect(resolveStatusCode({ expose: true, status: 413, type: 'entity.too.large' })).toBe(413);
  });

  it('does not trust non exposed error statuses', () => {
    expect(resolveStatusCode({ status: 404 })).toBe(500);
  });

  it('never exposes 5xx statuses from http-errors', () => {
    expect(resolveStatusCode({ expose: true, status: 503 })).toBe(500);
  });

  it('rejects nonsensical HttpException statuses', () => {
    expect(resolveStatusCode(new HttpException('teapot', 200))).toBe(500);
  });

  it('treats non error values as internal failures', () => {
    expect(resolveStatusCode('nope')).toBe(500);
    expect(resolveStatusCode(undefined)).toBe(500);
  });
});
