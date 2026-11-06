import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * The raw body parser for the one route that takes a file as its body.
 *
 * `express.raw` would be the obvious choice, but `express` is not a dependency
 * of this project - it arrives only through `@nestjs/platform-express`, whose
 * copy pnpm does not expose at the root - so this is the same idea written
 * against the request stream: read only the media types the route accepts, keep
 * at most the upload limit in memory, and hand the bytes on as one Buffer.
 * Anything past the limit is refused, and past twice the limit it is not even
 * read.
 *
 * Failures are raised with the same `type` values `createBodyParserErrorHandler`
 * already maps, so an oversized upload leaves through the identical generic 413
 * envelope every other body-parser refusal uses.
 */

/** Shaped like the body-parser errors the shared mapper understands. */
interface BodyParserError extends Error {
  readonly type: string;
  readonly status: number;
}

function bodyParserError(type: string, status: number, message: string): BodyParserError {
  return Object.assign(new Error(message), { type, status });
}

/** Too large: refused by `createBodyParserErrorHandler` as a generic 413. */
export function tooLargeError(): BodyParserError {
  return bodyParserError('entity.too.large', 413, 'request entity too large');
}

/** The client went away mid-body: refused as a generic 400. */
export function abortedError(): BodyParserError {
  return bodyParserError('request.aborted', 400, 'request aborted');
}

export interface RawBodyOptions {
  /** The only media types that are read; anything else is left unparsed. */
  readonly mediaTypes: readonly string[];
  /** Largest body accepted, in bytes. */
  readonly limitBytes: number;
}

/** `image/png; charset=binary` and `IMAGE/PNG` are the same media type. */
export function mediaTypeEssence(header: string | undefined): string {
  return (header ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
}

/**
 * The parser itself. A request it does not accept is passed on untouched - with
 * no `body` at all - so the handler can answer 415 without a byte being read.
 *
 * An oversized body is dropped as it arrives: what was buffered is released, the
 * rest is read and discarded, and the refusal is reported once the client has
 * finished sending. Answering earlier would leave the request half-read, and the
 * connection - not the envelope - would be what the client sees. A body that
 * keeps coming past that allowance is refused where it stands, so a stream
 * cannot be used to hold the socket open.
 */
export function createRawBodyMiddleware({
  mediaTypes,
  limitBytes,
}: RawBodyOptions): RequestHandler {
  // Twice the limit is the point where reading the rest is no longer a courtesy.
  const drainThreshold = limitBytes * 2;

  return (request: Request, _response: Response, next: NextFunction): void => {
    const accepted = mediaTypes.some(
      (type) => type === mediaTypeEssence(request.headers['content-type']),
    );

    if (!accepted) {
      next();
      return;
    }

    // A declared length this far over the limit is refused before it is read.
    const declared = Number(request.headers['content-length']);

    if (Number.isFinite(declared) && declared > drainThreshold) {
      next(tooLargeError());
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let discarded = 0;
    let overLimit = false;
    let settled = false;

    const settle = (error?: BodyParserError): void => {
      if (settled) return;

      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.removeListener('error', onAborted);
      request.removeListener('aborted', onAborted);

      if (error !== undefined) {
        // Stop reading: the answer is already decided and the rest is dropped.
        request.pause();
        next(error);
        return;
      }

      (request as { body?: unknown }).body = Buffer.concat(chunks, size);
      next();
    };

    function onData(chunk: Buffer): void {
      if (overLimit) {
        discarded += chunk.length;

        if (discarded > limitBytes) settle(tooLargeError());

        return;
      }

      size += chunk.length;

      if (size > limitBytes) {
        overLimit = true;
        chunks.length = 0;
        return;
      }

      chunks.push(chunk);
    }

    function onEnd(): void {
      settle(overLimit ? tooLargeError() : undefined);
    }

    function onAborted(): void {
      settle(abortedError());
    }

    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', onAborted);
    request.on('aborted', onAborted);
  };
}
