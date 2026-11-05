import { sanitizeImage } from './image-sanitizer';
import { detectImageType } from './image-type';
import { DocumentIngestError } from './ingest.errors';
import {
  buildJpeg,
  buildPng,
  COMMENT_SEGMENT,
  EXIF_CHUNK,
  EXIF_SEGMENT,
  pngChunks,
  TEXT_CHUNK,
} from './testing/image-fixtures';

describe('sanitizeImage', () => {
  it('sends a JPEG through the JPEG sanitizer', () => {
    const bytes = buildJpeg({ segments: [EXIF_SEGMENT, COMMENT_SEGMENT] });

    expect(sanitizeImage('jpeg', bytes).equals(buildJpeg())).toBe(true);
  });

  it('sends a PNG through the PNG sanitizer', () => {
    const bytes = buildPng({ chunks: [TEXT_CHUNK, EXIF_CHUNK] });

    expect(sanitizeImage('png', bytes).equals(buildPng())).toBe(true);
  });

  it('strips what the detector said the file was', () => {
    // The whole point of the pair: detect, then sanitize the same bytes.
    const bytes = buildPng({ chunks: [TEXT_CHUNK] });
    const output = sanitizeImage(detectImageType(bytes), bytes);

    expect(pngChunks(output).map((chunk) => chunk.type)).toEqual(['IHDR', 'IDAT', 'IEND']);
  });

  it('refuses bytes that are not the type it was given', () => {
    expect(() => sanitizeImage('png', buildJpeg())).toThrow(DocumentIngestError);
    expect(() => sanitizeImage('jpeg', buildPng())).toThrow(DocumentIngestError);
  });
});
