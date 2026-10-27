import type { NextFunction, Request, Response } from 'express';
import {
  createBodyParserErrorHandler,
  resolveBodyParserStatus,
  type RequestLogger,
} from './body-parser-error.middleware';

const REQUEST_ID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

function createResponse(headersSent = false) {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));

  return { response: { headersSent, status } as unknown as Response, status, json };
}

function createRequest(): Request {
  return {
    id: REQUEST_ID,
    method: 'POST',
    originalUrl: '/test/echo?token=abc',
    url: '/test/echo?token=abc',
  } as unknown as Request;
}

function createLogger(): { logger: RequestLogger; warn: jest.Mock } {
  const warn = jest.fn();

  return { logger: { warn } satisfies RequestLogger, warn };
}

function bodyParserError(type: string): Error {
  return Object.assign(new Error(`raw message for ${type}`), {
    type,
    status: 400,
    statusCode: 400,
    expose: true,
  });
}

describe('resolveBodyParserStatus', () => {
  it.each([
    ['entity.too.large', 413],
    ['parameters.too.many', 413],
    ['entity.parse.failed', 400],
    ['request.aborted', 400],
    ['charset.unsupported', 415],
    ['encoding.unsupported', 415],
  ])('maps %s to %i', (type, expected) => {
    expect(resolveBodyParserStatus(bodyParserError(type))).toBe(expected);
  });

  it('ignores unknown error types', () => {
    expect(resolveBodyParserStatus(bodyParserError('something.else'))).toBeUndefined();
    expect(resolveBodyParserStatus(new Error('plain'))).toBeUndefined();
    expect(resolveBodyParserStatus('nope')).toBeUndefined();
    expect(resolveBodyParserStatus(null)).toBeUndefined();
  });
});

describe('createBodyParserErrorHandler', () => {
  it('returns a generic 413 envelope without leaking the parser message', () => {
    const { logger, warn } = createLogger();
    const { response, status, json } = createResponse();
    const next = jest.fn() as unknown as NextFunction;

    createBodyParserErrorHandler(logger)(
      bodyParserError('entity.too.large'),
      createRequest(),
      response,
      next,
    );

    expect(status).toHaveBeenCalledWith(413);
    expect(json).toHaveBeenCalledWith({
      statusCode: 413,
      message: 'Payload Too Large',
      requestId: REQUEST_ID,
    });
    expect(next).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('maps malformed JSON to a generic 400', () => {
    const { logger } = createLogger();
    const { response, status, json } = createResponse();

    createBodyParserErrorHandler(logger)(
      bodyParserError('entity.parse.failed'),
      createRequest(),
      response,
      jest.fn() as unknown as NextFunction,
    );

    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      statusCode: 400,
      message: 'Bad Request',
      requestId: REQUEST_ID,
    });
  });

  it('logs the path without the query string', () => {
    const { logger, warn } = createLogger();

    createBodyParserErrorHandler(logger)(
      bodyParserError('entity.too.large'),
      createRequest(),
      createResponse().response,
      jest.fn() as unknown as NextFunction,
    );

    const payload = warn.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({
      msg: 'request rejected before routing',
      requestId: REQUEST_ID,
      statusCode: 413,
      path: '/test/echo',
    });
    expect(payload.err).toBeInstanceOf(Error);
  });

  it('delegates unknown errors to the next error handler', () => {
    const { logger } = createLogger();
    const { response, status, json } = createResponse();
    const error = new Error('not a body parser error');
    const next = jest.fn();

    createBodyParserErrorHandler(logger)(error, createRequest(), response, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('does not write a response when headers were already sent', () => {
    const { logger } = createLogger();
    const { response, status } = createResponse(true);

    createBodyParserErrorHandler(logger)(
      bodyParserError('entity.too.large'),
      createRequest(),
      response,
      jest.fn() as unknown as NextFunction,
    );

    expect(status).not.toHaveBeenCalled();
  });
});
