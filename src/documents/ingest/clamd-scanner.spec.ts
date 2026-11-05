import { CLAMD_CHUNK_BYTES, ClamdScanner } from './clamd-scanner';
import { DocumentIngestError } from './ingest.errors';
import { FakeClamdServer } from './testing/fake-clamd';

/** Filler with no meaning; the scanner never looks at the content. */
const PAYLOAD = Buffer.from('test-only payload, never a real document', 'latin1');

/** Short timeouts: no test should wait seconds to watch a socket give up. */
const FAST_TIMEOUTS = { connectTimeoutMs: 200, idleTimeoutMs: 200, totalTimeoutMs: 2_000 };

/**
 * Awaits a scan and hands back the error it was rejected with, so a test can
 * assert on the error itself and not only on the fact that there is one.
 */
async function rejectionOf(scan: Promise<void>): Promise<Error> {
  try {
    await scan;
  } catch (error) {
    return error as Error;
  }

  throw new Error('expected the scan to be rejected');
}

describe('ClamdScanner', () => {
  let daemon: FakeClamdServer | undefined;

  afterEach(async () => {
    await daemon?.close();
    daemon = undefined;
  });

  it('accepts a clean verdict and frames the stream the way clamd expects', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: OK\0' });

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).resolves.toBeUndefined();

    expect(daemon.command).toBe('zINSTREAM\0');
    expect(daemon.chunks).toHaveLength(1);
    expect(daemon.uploaded.equals(PAYLOAD)).toBe(true);
    expect(daemon.terminated).toBe(true);
  });

  it('sends a large upload as frames of at most 64 KiB', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: OK\0' });

    const large = Buffer.alloc(2 * CLAMD_CHUNK_BYTES + 123, 0x21);

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(large),
    ).resolves.toBeUndefined();

    expect(daemon.chunks).toHaveLength(3);

    for (const chunk of daemon.chunks) {
      expect(chunk.length).toBeGreaterThan(0);
      expect(chunk.length).toBeLessThanOrEqual(CLAMD_CHUNK_BYTES);
    }

    expect(daemon.uploaded.equals(large)).toBe(true);
    expect(daemon.terminated).toBe(true);
  });

  it('rejects when the daemon reports a signature', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: test-only-signature FOUND\0' });

    const error = await rejectionOf(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    );

    expect(error).toBeInstanceOf(DocumentIngestError);
    expect(error.message).toBe('Upload rejected');
    // The signature name must not travel any further than this client.
    expect(error.message).not.toContain('test-only-signature');
  });

  it('rejects an unreadable reply', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: ???\0' });

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('rejects a size-limit complaint instead of reading it as clean', async () => {
    daemon = await FakeClamdServer.start({ reply: 'INSTREAM size limit exceeded. ERROR\0' });

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('rejects a connection that is closed without a verdict', async () => {
    daemon = await FakeClamdServer.start({ hangUpOnConnect: true });

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('rejects a daemon that never answers', async () => {
    daemon = await FakeClamdServer.start({ silent: true });

    const started = Date.now();

    await expect(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).rejects.toBeInstanceOf(DocumentIngestError);

    // The idle watchdog is what ended the wait, not the hard cap.
    expect(Date.now() - started).toBeLessThan(FAST_TIMEOUTS.totalTimeoutMs);
  });

  it('rejects when nothing is listening', async () => {
    const closed = await FakeClamdServer.start();

    await closed.close();

    await expect(
      new ClamdScanner('127.0.0.1', closed.port, FAST_TIMEOUTS).scan(PAYLOAD),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('closes the socket after a clean verdict', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: OK\0' });

    await new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD);
    await daemon.clientClosed();
  });

  it('closes the socket after a rejected scan', async () => {
    daemon = await FakeClamdServer.start({ reply: 'stream: ???\0' });

    await rejectionOf(new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS).scan(PAYLOAD));
    await daemon.clientClosed();
  });
});
