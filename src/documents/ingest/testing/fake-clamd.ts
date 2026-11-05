import { createServer, type Server, type Socket } from 'node:net';

/** How the fake daemon answers once the whole stream has arrived. */
export interface FakeClamdOptions {
  /** Bytes written back after the zero-length terminator; `stream: OK` by default. */
  readonly reply?: string;
  /** Accept the upload and never answer, for the timeout checks. */
  readonly silent?: boolean;
  /** Hang up as soon as a client connects, for the broken-pipe check. */
  readonly hangUpOnConnect?: boolean;
}

/**
 * A clamd stand-in for the tests: a loopback socket that speaks INSTREAM.
 *
 * It keeps what it received - the command, the payload of every frame and
 * whether the zero-length terminator arrived - so a test can check the framing
 * instead of trusting the client. Nothing leaves 127.0.0.1 and nothing has to be
 * installed: the whole daemon is this class.
 */
export class FakeClamdServer {
  private readonly server: Server;
  private readonly sockets: Socket[] = [];
  private readonly payloads: Buffer[] = [];
  private commandText = '';
  private terminatedSeen = false;
  private unread: Buffer = Buffer.alloc(0);

  constructor(private readonly options: FakeClamdOptions = {}) {
    this.server = createServer((socket) => this.accept(socket));
  }

  static async start(options: FakeClamdOptions = {}): Promise<FakeClamdServer> {
    const fake = new FakeClamdServer(options);

    await new Promise<void>((resolve) => fake.server.listen(0, '127.0.0.1', () => resolve()));

    return fake;
  }

  get port(): number {
    const address = this.server.address();

    return typeof address === 'object' && address !== null ? address.port : 0;
  }

  /** The command exactly as it arrived, terminator included. */
  get command(): string {
    return this.commandText;
  }

  /** The payload of every frame, in the order they arrived. */
  get chunks(): readonly Buffer[] {
    return this.payloads;
  }

  /** Whether the zero-length terminator arrived. */
  get terminated(): boolean {
    return this.terminatedSeen;
  }

  /** Everything the client sent, i.e. what the daemon would have scanned. */
  get uploaded(): Buffer {
    return Buffer.concat(this.payloads);
  }

  /** Resolves when the client hangs up. */
  clientClosed(): Promise<void> {
    const socket = this.sockets[0];

    if (socket === undefined || socket.closed) return Promise.resolve();

    return new Promise<void>((resolve) => socket.once('close', () => resolve()));
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();

    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private accept(socket: Socket): void {
    this.sockets.push(socket);

    if (this.options.hangUpOnConnect === true) {
      socket.destroy();
      return;
    }

    // The client is expected to hang up once it has its answer.
    socket.on('error', () => undefined);
    socket.on('data', (data: Buffer) => this.receive(socket, data));
  }

  private receive(socket: Socket, data: Buffer): void {
    if (this.terminatedSeen) return;

    this.unread = Buffer.concat([this.unread, data]);

    if (this.commandText === '') {
      const end = this.unread.indexOf(0);

      if (end === -1) return;

      this.commandText = this.unread.subarray(0, end + 1).toString('latin1');
      this.unread = this.unread.subarray(end + 1);
    }

    while (this.unread.length >= 4) {
      const length = this.unread.readUInt32BE(0);

      if (length === 0) {
        this.terminatedSeen = true;
        this.unread = this.unread.subarray(4);

        if (this.options.silent !== true) {
          socket.write(this.options.reply ?? 'stream: OK\0');
        }

        return;
      }

      if (this.unread.length < 4 + length) return;

      this.payloads.push(Buffer.from(this.unread.subarray(4, 4 + length)));
      this.unread = this.unread.subarray(4 + length);
    }
  }
}
