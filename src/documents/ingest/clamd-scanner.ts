import { createConnection } from 'node:net';
import { DocumentIngestError } from './ingest.errors';
import type { VirusScanner } from './virus-scanner';

/**
 * `VirusScanner` over the clamd INSTREAM protocol.
 *
 * Why INSTREAM: the bytes are already in memory, and streaming them means the
 * scanner never needs a shared volume and no temporary file of an identity
 * document is ever written to disk.
 *
 * The client FAILS CLOSED. Only an explicit `stream: OK` lets an upload through;
 * an infection, a size-limit complaint, a daemon error, an unreadable reply, a
 * closed connection, a refused connection and every timeout are all a rejection.
 *
 * Nothing here is logged and no error carries anything but the generic ingest
 * message: the signature name and the scanned bytes stay out of both.
 */

/** Time allowed to establish the TCP connection. */
export const CLAMD_CONNECT_TIMEOUT_MS = 2_000;

/** Time the daemon may stay silent before the scan is abandoned. */
export const CLAMD_IDLE_TIMEOUT_MS = 15_000;

/** Hard cap on one scan, from connect to verdict, whatever the daemon does. */
export const CLAMD_TOTAL_TIMEOUT_MS = 30_000;

/**
 * Largest payload per length-prefixed frame.
 *
 * clamd's own INSTREAM limit is 128 KiB; staying well below it keeps the framing
 * valid without tuning the daemon, and keeps the 4-byte length field honest.
 */
export const CLAMD_CHUNK_BYTES = 64 * 1024;

/** The command is null-terminated, which is how clamd knows where it ends. */
const COMMAND = 'zINSTREAM\0';

/** The only reply that means "nothing found". */
const CLEAN_REPLY = 'stream: OK';

/** Present in every infected reply, right before the signature name that is dropped. */
const INFECTED_REPLY = 'FOUND';

/** Replies are null-terminated too. */
const REPLY_END = '\0';

/** What one reply line means. */
type Verdict = 'clean' | 'infected' | 'failure';

/**
 * Reads one reply: `stream: OK` is clean, an answer naming a signature is an
 * infection, and everything else - `INSTREAM size limit exceeded. ERROR`, a
 * daemon error, gibberish - is a scanner failure.
 *
 * The distinction is made here and then dropped: all three non-clean verdicts
 * become the same rejection, so a caller cannot tell an infection from an outage
 * and the signature name never travels.
 */
function verdictOf(reply: string): Verdict {
  if (reply === CLEAN_REPLY) return 'clean';
  if (reply.includes(INFECTED_REPLY)) return 'infected';

  return 'failure';
}

/**
 * Frames one upload: the command, then each chunk behind its 4-byte big-endian
 * length, then a zero length to say "that was all".
 */
function frame(bytes: Buffer): Buffer[] {
  const parts: Buffer[] = [Buffer.from(COMMAND, 'latin1')];

  for (let offset = 0; offset < bytes.length; offset += CLAMD_CHUNK_BYTES) {
    const end = Math.min(offset + CLAMD_CHUNK_BYTES, bytes.length);
    const length = Buffer.alloc(4);

    length.writeUInt32BE(end - offset, 0);
    parts.push(length, bytes.subarray(offset, end));
  }

  // A zero length frame is the end of the stream, and clamd answers after it.
  parts.push(Buffer.alloc(4));

  return parts;
}

export interface ClamdScannerOptions {
  readonly connectTimeoutMs?: number;
  readonly idleTimeoutMs?: number;
  readonly totalTimeoutMs?: number;
}

export class ClamdScanner implements VirusScanner {
  private readonly connectTimeoutMs: number;
  private readonly idleTimeoutMs: number;
  private readonly totalTimeoutMs: number;

  constructor(
    private readonly host: string,
    private readonly port: number,
    options: ClamdScannerOptions = {},
  ) {
    this.connectTimeoutMs = options.connectTimeoutMs ?? CLAMD_CONNECT_TIMEOUT_MS;
    this.idleTimeoutMs = options.idleTimeoutMs ?? CLAMD_IDLE_TIMEOUT_MS;
    this.totalTimeoutMs = options.totalTimeoutMs ?? CLAMD_TOTAL_TIMEOUT_MS;
  }

  /** Resolves on `stream: OK`; rejects on every other outcome. */
  scan(bytes: Buffer): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = createConnection({ host: this.host, port: this.port });

      let reply = '';
      let settled = false;
      let connectTimer: NodeJS.Timeout | undefined;
      let idleTimer: NodeJS.Timeout | undefined;
      let totalTimer: NodeJS.Timeout | undefined;

      // The only way out of this promise. Every path - verdict, error, timeout,
      // hang-up - goes through here, so the socket is always destroyed and the
      // promise settles exactly once.
      const finish = (error?: DocumentIngestError): void => {
        if (settled) return;

        settled = true;

        for (const timer of [connectTimer, idleTimer, totalTimer]) {
          if (timer !== undefined) clearTimeout(timer);
        }

        connectTimer = undefined;
        idleTimer = undefined;
        totalTimer = undefined;

        socket.destroy();

        if (error === undefined) resolve();
        else reject(error);
      };

      /** Restarts the silence watchdog; called on connect and on every read. */
      const armIdleTimer = (): void => {
        if (idleTimer !== undefined) clearTimeout(idleTimer);

        idleTimer = setTimeout(() => finish(new DocumentIngestError()), this.idleTimeoutMs);
      };

      const settleFromReply = (text: string): void => {
        const verdict = verdictOf(text.trim());

        // An infection and a broken scanner are refused identically on purpose:
        // the caller learns nothing, and the signature name is dropped here.
        if (verdict === 'clean') finish();
        else finish(new DocumentIngestError());
      };

      /** Appends a reply fragment and settles once the whole answer has arrived. */
      const consume = (chunk: Buffer): void => {
        reply += chunk.toString('latin1');

        const end = reply.indexOf(REPLY_END);

        if (end === -1) return;

        settleFromReply(reply.slice(0, end));
      };

      // Chunks are written in order and the reply is read asynchronously, so the
      // upload can be queued in one pass without waiting for a drain.
      socket.on('connect', () => {
        if (connectTimer !== undefined) clearTimeout(connectTimer);

        connectTimer = undefined;

        armIdleTimer();

        for (const part of frame(bytes)) socket.write(part);
      });

      socket.on('data', (chunk: Buffer) => {
        armIdleTimer();
        consume(chunk);
      });

      // A connection that ends is never a clean verdict, but a daemon that closes
      // right after a complete answer is still readable: only a reply without its
      // terminator gets one last chance here.
      socket.on('close', () => {
        if (!settled && reply.length > 0) settleFromReply(reply);

        finish(new DocumentIngestError());
      });

      socket.on('error', () => finish(new DocumentIngestError()));

      connectTimer = setTimeout(() => finish(new DocumentIngestError()), this.connectTimeoutMs);
      totalTimer = setTimeout(() => finish(new DocumentIngestError()), this.totalTimeoutMs);
    });
  }
}
