import { createHash } from 'node:crypto';
import { ClamdScanner } from './clamd-scanner';
import { DocumentIngestService } from './document-ingest.service';
import { MAX_UPLOAD_BYTES } from './ingest.constants';
import { DocumentIngestError } from './ingest.errors';
import { FakeClamdServer } from './testing/fake-clamd';
import { EXIF_CHUNK, EXIF_SEGMENT, buildJpeg, buildPng } from './testing/image-fixtures';
import { FakeVirusScanner } from './testing/fake-virus-scanner';

/** The string the metadata fixtures carry; it must never survive the pipeline. */
const EXIF_MARKER = 'test-only exif';

/** Short timeouts for the one test that talks to a closed loopback port. */
const FAST_TIMEOUTS = { connectTimeoutMs: 500, idleTimeoutMs: 500, totalTimeoutMs: 5_000 };

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** A JPEG with the metadata a phone attaches: EXIF, GPS, a comment. */
function taggedJpeg(): Buffer {
  return buildJpeg({ segments: [EXIF_SEGMENT] });
}

/** Awaits a rejected ingest and hands back the error, for message assertions. */
async function rejectionOf(ingest: Promise<unknown>): Promise<Error> {
  try {
    await ingest;
  } catch (error) {
    return error as Error;
  }

  throw new Error('expected the upload to be rejected');
}

describe('DocumentIngestService', () => {
  it('strips the metadata, names the type and hashes what it returns', async () => {
    const scanner = new FakeVirusScanner();
    const upload = taggedJpeg();

    const result = await new DocumentIngestService(scanner).process({ bytes: upload });

    expect(upload.toString('latin1')).toContain(EXIF_MARKER);
    expect(result.type).toBe('jpeg');
    expect(result.bytes.toString('latin1')).not.toContain(EXIF_MARKER);
    expect(result.bytes.length).toBeLessThan(upload.length);
    expect(result.sha256).toBe(sha256(result.bytes));
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('scans the sanitized bytes, not the upload', async () => {
    const scanner = new FakeVirusScanner();
    const upload = taggedJpeg();

    const result = await new DocumentIngestService(scanner).process({ bytes: upload });
    const [scanned] = scanner.received;

    expect(scanner.received).toHaveLength(1);
    expect(scanned).toBeDefined();
    // The scanner saw the file that would be stored: a payload hidden in a
    // dropped segment never reaches it, and an infection in the kept bytes does.
    expect(scanned?.equals(result.bytes)).toBe(true);
    expect(scanned?.equals(upload)).toBe(false);
    expect(scanned?.toString('latin1')).not.toContain(EXIF_MARKER);
  });

  it('strips the metadata out of a PNG before the scan', async () => {
    const scanner = new FakeVirusScanner();
    const upload = buildPng({ chunks: [EXIF_CHUNK] });

    const result = await new DocumentIngestService(scanner).process({ bytes: upload });
    const [scanned] = scanner.received;

    expect(upload.toString('latin1')).toContain(EXIF_MARKER);
    expect(result.type).toBe('png');
    expect(scanned?.toString('latin1')).not.toContain(EXIF_MARKER);
    expect(scanned?.equals(result.bytes)).toBe(true);
  });

  it('rejects the whole upload when the scan fails', async () => {
    const scanner = new FakeVirusScanner('failing');

    await expect(
      new DocumentIngestService(scanner).process({ bytes: taggedJpeg() }),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('rejects an infected upload and says nothing about it', async () => {
    const scanner = new FakeVirusScanner('infected');

    const error = await rejectionOf(
      new DocumentIngestService(scanner).process({ bytes: taggedJpeg() }),
    );

    expect(error).toBeInstanceOf(DocumentIngestError);
    expect(error.message).toBe('Upload rejected');
    expect(scanner.received).toHaveLength(1);
  });

  it('refuses to process anything when no scanner is configured', async () => {
    await expect(
      new DocumentIngestService().process({ bytes: taggedJpeg() }),
    ).rejects.toBeInstanceOf(DocumentIngestError);

    // An environment without CLAMAV_* is a service without a scanner: fail closed.
    await expect(
      DocumentIngestService.fromEnv({}).process({ bytes: taggedJpeg() }),
    ).rejects.toBeInstanceOf(DocumentIngestError);
    await expect(
      DocumentIngestService.fromEnv({ CLAMAV_HOST: '127.0.0.1' }).process({ bytes: taggedJpeg() }),
    ).rejects.toBeInstanceOf(DocumentIngestError);
  });

  it('checks the size before a byte is parsed', async () => {
    const scanner = new FakeVirusScanner();
    // A structurally valid PNG whose pixels push it past the cap: the only reason
    // to refuse it is the size gate, so nothing else may have run.
    const oversized = buildPng({
      chunks: [{ type: 'IDAT', data: Buffer.alloc(MAX_UPLOAD_BYTES, 0x21) }],
    });

    expect(oversized.length).toBeGreaterThan(MAX_UPLOAD_BYTES);

    await expect(
      new DocumentIngestService(scanner).process({ bytes: oversized, claimedExtension: 'png' }),
    ).rejects.toBeInstanceOf(DocumentIngestError);
    expect(scanner.received).toHaveLength(0);
  });

  it('never mutates the upload', async () => {
    const upload = buildPng({ chunks: [EXIF_CHUNK] });
    const before = Buffer.from(upload);

    await new DocumentIngestService(new FakeVirusScanner()).process({ bytes: upload });

    expect(upload.equals(before)).toBe(true);
  });

  it('rejects a claim that contradicts the bytes without scanning', async () => {
    const scanner = new FakeVirusScanner();

    await expect(
      new DocumentIngestService(scanner).process({
        bytes: buildPng(),
        claimedExtension: 'jpg',
        claimedMime: 'image/jpeg',
      }),
    ).rejects.toBeInstanceOf(DocumentIngestError);

    expect(scanner.received).toHaveLength(0);
  });

  it('accepts claims that agree with the bytes', async () => {
    const scanner = new FakeVirusScanner();

    const result = await new DocumentIngestService(scanner).process({
      bytes: buildJpeg(),
      claimedExtension: '.jpeg',
      claimedMime: 'image/jpeg',
    });

    expect(result.type).toBe('jpeg');
    expect(scanner.received).toHaveLength(1);
  });

  it('uses the configured clamd daemon when one is set', async () => {
    const daemon = await FakeClamdServer.start({ reply: 'stream: OK\0' });

    try {
      const service = DocumentIngestService.fromEnv({
        CLAMAV_HOST: '127.0.0.1',
        CLAMAV_PORT: daemon.port,
      });

      const result = await service.process({ bytes: taggedJpeg() });

      // The daemon received exactly the bytes the pipeline would store.
      expect(daemon.uploaded.equals(result.bytes)).toBe(true);
    } finally {
      await daemon.close();
    }
  });

  it('refuses when the configured clamd daemon is unreachable', async () => {
    const daemon = await FakeClamdServer.start();

    await daemon.close();

    const service = new DocumentIngestService(
      new ClamdScanner('127.0.0.1', daemon.port, FAST_TIMEOUTS),
    );

    await expect(service.process({ bytes: taggedJpeg() })).rejects.toBeInstanceOf(
      DocumentIngestError,
    );
  });
});
