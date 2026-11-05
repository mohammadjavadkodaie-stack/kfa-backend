import { DocumentIngestError } from './ingest.errors';
import { sanitizeJpeg } from './jpeg-sanitizer';
import {
  buildJpeg,
  COMMENT_SEGMENT,
  EXIF_SEGMENT,
  ICC_SEGMENT,
  jpegMarkers,
  jpegSegment,
  jpegWithSegmentLength,
  truncatedTo,
  withTrailingBytes,
  XMP_SEGMENT,
} from './testing/image-fixtures';

/**
 * The marker sequence a stripped image still has: APP0/JFIF, DQT, SOF0, DHT,
 * SOS and EOI. Nothing else may appear between them.
 */
const KEPT_MARKERS = [0xe0, 0xdb, 0xc0, 0xc4, 0xda, 0xd9];

describe('sanitizeJpeg', () => {
  it('returns the image unchanged when there is no metadata to strip', () => {
    const bytes = buildJpeg();

    expect(sanitizeJpeg(bytes).equals(bytes)).toBe(true);
  });

  it('drops EXIF, XMP, ICC and comment segments', () => {
    const bytes = buildJpeg({
      segments: [EXIF_SEGMENT, XMP_SEGMENT, ICC_SEGMENT, COMMENT_SEGMENT],
    });

    // The input really does carry all four ...
    expect(jpegMarkers(bytes)).toEqual([0xe1, 0xe1, 0xe2, 0xfe, ...KEPT_MARKERS]);
    expect(bytes.includes(Buffer.from('test-only exif'))).toBe(true);

    const output = sanitizeJpeg(bytes);

    // ... and none of it survives.
    expect(jpegMarkers(output)).toEqual(KEPT_MARKERS);
    expect(output.includes(Buffer.from('test-only exif'))).toBe(false);
    expect(output.includes(Buffer.from('xmpmeta'))).toBe(false);
    expect(output.includes(Buffer.from('ICC_PROFILE'))).toBe(false);
    expect(output.includes(Buffer.from('test-only comment'))).toBe(false);
  });

  it('keeps the segments and the scan data byte for byte', () => {
    const withMetadata = buildJpeg({ segments: [EXIF_SEGMENT, XMP_SEGMENT, COMMENT_SEGMENT] });

    expect(sanitizeJpeg(withMetadata).equals(buildJpeg())).toBe(true);
  });

  it('drops an APP0 segment that is not the JFIF header', () => {
    const thumbnail = jpegSegment(0xe0, Buffer.from('JFXX\0test-only thumbnail', 'latin1'));
    const output = sanitizeJpeg(buildJpeg({ segments: [thumbnail] }));

    expect(output.equals(buildJpeg())).toBe(true);
  });

  it('rejects bytes that follow the end of the image', () => {
    const bytes = buildJpeg();

    for (const extra of [
      Buffer.from([0x00]),
      Buffer.from('test-only', 'latin1'),
      Buffer.from([0xff, 0xd9]),
    ]) {
      expect(() => sanitizeJpeg(withTrailingBytes(bytes, extra))).toThrow(DocumentIngestError);
    }
  });

  it('rejects a truncated image', () => {
    const bytes = buildJpeg();

    // One byte short of EOI, three short, inside the header, and after SOI.
    for (const length of [bytes.length - 1, bytes.length - 3, 20, 2]) {
      expect(() => sanitizeJpeg(truncatedTo(bytes, length))).toThrow(DocumentIngestError);
    }
  });

  it('rejects a segment length that lies', () => {
    // Longer than the file, and shorter than the two bytes the field occupies.
    expect(() => sanitizeJpeg(jpegWithSegmentLength(0x1000))).toThrow(DocumentIngestError);
    expect(() => sanitizeJpeg(jpegWithSegmentLength(0))).toThrow(DocumentIngestError);
  });

  it('rejects a file that does not start with SOI', () => {
    const bytes = buildJpeg();

    expect(() => sanitizeJpeg(bytes.subarray(2))).toThrow(DocumentIngestError);
    expect(() => sanitizeJpeg(Buffer.from([0xff, 0xd8]))).toThrow(DocumentIngestError);
  });

  it('rejects an image whose frame header is too large', () => {
    // A side over the cap, and a canvas over the pixel cap with both sides legal.
    expect(() => sanitizeJpeg(buildJpeg({ width: 20_000 }))).toThrow(DocumentIngestError);
    expect(() => sanitizeJpeg(buildJpeg({ width: 4_001, height: 10_000 }))).toThrow(
      DocumentIngestError,
    );

    // Exactly on the pixel cap is still accepted.
    expect(() => sanitizeJpeg(buildJpeg({ width: 10_000, height: 4_000 }))).not.toThrow();
  });

  it('does not touch the buffer it was given', () => {
    const bytes = buildJpeg({ segments: [EXIF_SEGMENT, COMMENT_SEGMENT] });
    const before = Buffer.from(bytes);

    const output = sanitizeJpeg(bytes);

    expect(bytes.equals(before)).toBe(true);
    expect(output).not.toBe(bytes);
  });
});
