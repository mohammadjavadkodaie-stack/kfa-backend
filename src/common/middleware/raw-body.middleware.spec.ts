import { EventEmitter } from 'node:events';
import type { NextFunction, Request, Response } from 'express';
import { resolveBodyParserStatus } from './body-parser-error.middleware';
import {
  abortedError,
  createRawBodyMiddleware,
  mediaTypeEssence,
  tooLargeError,
} from './raw-body.middleware';

/** The two types the upload route takes, and a limit small enough to read. */
const OPTIONS = { mediaTypes: ['image/jpeg', 'image/png'], limitBytes: 8 };

/** Just enough of an incoming message: headers, a body slot and the pause hook. */
class FakeRequest extends EventEmitter {
  body?: unknown;
  pauses = 0;

  constructor(private readonly incoming: Record<string, string | undefined>) {
    super();
  }

  get headers(): Record<string, string | undefined> {
    return this.incoming;
  }

  pause(): void {
    this.pauses += 1;
  }
}

function run(request: FakeRequest): jest.Mock {
  const next = jest.fn<void, [unknown?]>();

  createRawBodyMiddleware(OPTIONS)(
    request as unknown as Request,
    {} as Response,
    next as unknown as NextFunction,
  );

  return next;
}

function requestFor(contentType?: string, headers: Record<string, string> = {}): FakeRequest {
  return new FakeRequest({
    ...(contentType === undefined ? {} : { 'content-type': contentType }),
    ...headers,
  });
}

describe('mediaTypeEssence', () => {
  it.each([
    ['image/png', 'image/png'],
    ['image/png; charset=binary', 'image/png'],
    ['IMAGE/JPEG ; foo=bar', 'image/jpeg'],
    ['  image/jpeg  ', 'image/jpeg'],
    ['', ''],
    [undefined, ''],
  ])('reduces %p to %p', (header, expected) => {
    expect(mediaTypeEssence(header)).toBe(expected);
  });
});

describe('raw body middleware', () => {
  it('leaves a media type it does not accept completely alone', () => {
    const request = requestFor('text/plain');
    const next = run(request);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    // No listener, so the body is never read and the handler can answer 415.
    expect(request.listenerCount('data')).toBe(0);
    expect(request.body).toBeUndefined();
  });

  it('reads an accepted type and leaves the bytes on the request', () => {
    const request = requestFor('image/png; charset=binary');
    const next = run(request);

    request.emit('data', Buffer.from([1, 2, 3]));
    request.emit('data', Buffer.from([4, 5]));
    request.emit('end');

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(request.body).toEqual(Buffer.from([1, 2, 3, 4, 5]));
  });

  it('accepts a body of exactly the limit', () => {
    const request = requestFor('image/jpeg');
    const next = run(request);

    request.emit('data', Buffer.alloc(OPTIONS.limitBytes, 7));
    request.emit('end');

    expect(next).toHaveBeenCalledWith();
    expect((request.body as Buffer).length).toBe(OPTIONS.limitBytes);
  });

  it('drops a body one byte over the limit and reports a generic 413 at its end', () => {
    const request = requestFor('image/png');
    const next = run(request);

    request.emit('data', Buffer.alloc(4, 1));
    request.emit('data', Buffer.alloc(5, 2));

    // The rest is read and thrown away, so the client still gets an answer.
    expect(next).not.toHaveBeenCalled();

    request.emit('data', Buffer.alloc(3, 3));
    request.emit('end');

    expect(next).toHaveBeenCalledTimes(1);

    const [error] = next.mock.calls[0] ?? [];

    expect(resolveBodyParserStatus(error)).toBe(413);
    expect(request.body).toBeUndefined();
    // The body is already over: pausing an ended stream costs nothing.
    expect(request.pauses).toBe(1);
    expect(request.listenerCount('data')).toBe(0);
  });

  it('gives up on a body that keeps coming past the allowance', () => {
    const request = requestFor('image/png');
    const next = run(request);

    request.emit('data', Buffer.alloc(4, 1));
    request.emit('data', Buffer.alloc(9, 2));

    expect(next).not.toHaveBeenCalled();

    // Another limit's worth arrives: the connection is worth less than the answer.
    request.emit('data', Buffer.alloc(9, 3));

    const [error] = next.mock.calls[0] ?? [];

    expect(next).toHaveBeenCalledTimes(1);
    expect(resolveBodyParserStatus(error)).toBe(413);
    expect(request.pauses).toBe(1);
    expect(request.body).toBeUndefined();
    expect(request.listenerCount('data')).toBe(0);
  });

  it('refuses a declared length far over the limit without reading a byte', () => {
    const request = requestFor('image/png', { 'content-length': '17' });
    const next = run(request);

    const [error] = next.mock.calls[0] ?? [];

    expect(next).toHaveBeenCalledTimes(1);
    expect(resolveBodyParserStatus(error)).toBe(413);
    expect(request.listenerCount('data')).toBe(0);
    expect(request.body).toBeUndefined();
  });

  it('hands an empty body on as an empty buffer', () => {
    const request = requestFor('image/png');
    const next = run(request);

    request.emit('end');

    expect(next).toHaveBeenCalledWith();
    expect(request.body).toEqual(Buffer.alloc(0));
  });

  it('reports a request that went away as a generic 400', () => {
    const request = requestFor('image/png');
    const next = run(request);

    request.emit('data', Buffer.alloc(2, 1));
    request.emit('aborted');

    const [error] = next.mock.calls[0] ?? [];

    expect(next).toHaveBeenCalledTimes(1);
    expect(resolveBodyParserStatus(error)).toBe(400);
    expect(request.body).toBeUndefined();
  });
});

describe('raw body errors', () => {
  it('carries the types the shared mapper already knows', () => {
    expect(resolveBodyParserStatus(tooLargeError())).toBe(413);
    expect(resolveBodyParserStatus(abortedError())).toBe(400);
  });
});
