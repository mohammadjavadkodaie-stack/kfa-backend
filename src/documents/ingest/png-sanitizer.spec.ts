import { DocumentIngestError } from './ingest.errors';
import { sanitizePng } from './png-sanitizer';
import {
  buildPng,
  EXIF_CHUNK,
  expectedCrc,
  INTERNATIONAL_TEXT_CHUNK,
  PNG_SIGNATURE,
  pngChunk,
  pngChunks,
  TEXT_CHUNK,
  TIME_CHUNK,
  truncatedTo,
  withTrailingBytes,
} from './testing/image-fixtures';

/** The chunk sequence a stripped image still has. */
const KEPT_CHUNKS = ['IHDR', 'IDAT', 'IEND'];

describe('sanitizePng', () => {
  it('returns the image unchanged when there is no metadata to strip', () => {
    const bytes = buildPng();

    expect(sanitizePng(bytes).equals(bytes)).toBe(true);
  });

  it('drops text, international text, EXIF and time chunks', () => {
    const bytes = buildPng({
      chunks: [TEXT_CHUNK, INTERNATIONAL_TEXT_CHUNK, EXIF_CHUNK, TIME_CHUNK],
    });

    // The input really does carry all four ...
    expect(pngChunks(bytes).map((chunk) => chunk.type)).toEqual([
      'IHDR',
      'tEXt',
      'iTXt',
      'eXIf',
      'tIME',
      'IDAT',
      'IEND',
    ]);
    expect(bytes.includes(Buffer.from('test-only photo'))).toBe(true);

    const output = sanitizePng(bytes);

    // ... and none of it survives.
    expect(pngChunks(output).map((chunk) => chunk.type)).toEqual(KEPT_CHUNKS);
    expect(output.includes(Buffer.from('test-only photo'))).toBe(false);
    expect(output.includes(Buffer.from('test-only note'))).toBe(false);
    expect(output.includes(Buffer.from('test-only exif'))).toBe(false);
    expect(output.includes(Buffer.from('tIME'))).toBe(false);
  });

  it('keeps the pixels byte for byte', () => {
    const withMetadata = buildPng({ chunks: [TEXT_CHUNK, EXIF_CHUNK] });

    expect(sanitizePng(withMetadata).equals(buildPng())).toBe(true);
  });

  it('writes a correct CRC on every chunk it emits', () => {
    const output = sanitizePng(buildPng({ chunks: [TEXT_CHUNK, EXIF_CHUNK, TIME_CHUNK] }));

    expect(pngChunks(output)).toHaveLength(KEPT_CHUNKS.length);

    for (const chunk of pngChunks(output)) {
      expect(chunk.crc).toBe(expectedCrc(chunk));
    }
  });

  it('keeps the palette and the transparency chunk', () => {
    const palette = {
      type: 'PLTE',
      data: Buffer.from([0, 0, 0, 0xff, 0xff, 0xff, 0x33, 0x33, 0x33]),
    };
    const transparency = { type: 'tRNS', data: Buffer.from([0x00, 0xff, 0x33]) };
    const bytes = buildPng({ chunks: [palette, transparency] });

    const output = sanitizePng(bytes);

    expect(pngChunks(output).map((chunk) => chunk.type)).toEqual([
      'IHDR',
      'PLTE',
      'tRNS',
      'IDAT',
      'IEND',
    ]);
    // Nothing was stripped, so the rebuilt file matches the input byte for byte.
    expect(output.equals(bytes)).toBe(true);
  });

  it('drops the chunks that only describe how to display the image', () => {
    const bytes = buildPng({
      chunks: [
        { type: 'gAMA', data: Buffer.from([0x00, 0x00, 0xb1, 0x8f]) },
        { type: 'pHYs', data: Buffer.alloc(9, 0x01) },
        { type: 'iCCP', data: Buffer.from('test-only profile\0\0', 'latin1') },
        { type: 'prVt', data: Buffer.from('test-only private chunk', 'latin1') },
      ],
    });

    const output = sanitizePng(bytes);

    expect(pngChunks(output).map((chunk) => chunk.type)).toEqual(KEPT_CHUNKS);
    expect(output.includes(Buffer.from('test-only profile'))).toBe(false);
    expect(output.includes(Buffer.from('test-only private chunk'))).toBe(false);
  });

  it('rejects a chunk whose CRC does not match', () => {
    const bytes = buildPng({
      chunks: [{ type: 'tEXt', data: Buffer.from('Comment\0test-only', 'latin1'), crc: 0 }],
    });

    expect(() => sanitizePng(bytes)).toThrow(DocumentIngestError);
  });

  it('rejects a chunk that is damaged rather than intact', () => {
    const bytes = buildPng();
    const damaged = Buffer.from(bytes);

    // Flip one bit inside the pixel chunk: its CRC no longer covers the data.
    damaged[damaged.length - 20] = (damaged[damaged.length - 20] ?? 0) ^ 0x01;

    expect(() => sanitizePng(damaged)).toThrow(DocumentIngestError);
  });

  it('rejects an image without an end chunk', () => {
    expect(() => sanitizePng(buildPng({ omitEnd: true }))).toThrow(DocumentIngestError);
  });

  it('rejects bytes that follow the end chunk', () => {
    const bytes = buildPng();

    for (const extra of [
      Buffer.from([0x00]),
      Buffer.from('test-only', 'latin1'),
      pngChunk('tEXt', Buffer.from('Comment\0test-only', 'latin1')),
    ]) {
      expect(() => sanitizePng(withTrailingBytes(bytes, extra))).toThrow(DocumentIngestError);
    }
  });

  it('rejects a file that does not start with the header chunk', () => {
    const bytes = Buffer.concat([
      PNG_SIGNATURE,
      pngChunk('IDAT', Buffer.alloc(4)),
      pngChunk('IEND', Buffer.alloc(0)),
    ]);

    expect(() => sanitizePng(bytes)).toThrow(DocumentIngestError);
  });

  it('rejects a chunk type that is not four letters', () => {
    expect(() =>
      sanitizePng(buildPng({ chunks: [{ type: 'tx', data: Buffer.alloc(1) }] })),
    ).toThrow(DocumentIngestError);
  });

  it('rejects a wrong signature and a truncated file', () => {
    const bytes = buildPng();
    const wrongSignature = Buffer.from(bytes);

    wrongSignature[1] = 0x00;

    expect(() => sanitizePng(wrongSignature)).toThrow(DocumentIngestError);

    for (const length of [4, 20, 45, bytes.length - 1]) {
      expect(() => sanitizePng(truncatedTo(bytes, length))).toThrow(DocumentIngestError);
    }
  });

  it('rejects an image whose header is too large', () => {
    // A side over the cap, and a canvas over the pixel cap with both sides legal.
    expect(() => sanitizePng(buildPng({ width: 20_000 }))).toThrow(DocumentIngestError);
    expect(() => sanitizePng(buildPng({ width: 4_001, height: 10_000 }))).toThrow(
      DocumentIngestError,
    );

    // Exactly on the pixel cap is still accepted.
    expect(() => sanitizePng(buildPng({ width: 10_000, height: 4_000 }))).not.toThrow();
  });

  it('does not touch the buffer it was given', () => {
    const bytes = buildPng({ chunks: [TEXT_CHUNK, EXIF_CHUNK] });
    const before = Buffer.from(bytes);

    const output = sanitizePng(bytes);

    expect(bytes.equals(before)).toBe(true);
    expect(output).not.toBe(bytes);
  });
});
