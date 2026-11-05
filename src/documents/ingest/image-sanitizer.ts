import type { ImageType } from './image-type';
import { DocumentIngestError } from './ingest.errors';
import { sanitizeJpeg } from './jpeg-sanitizer';
import { sanitizePng } from './png-sanitizer';

/**
 * Strips the metadata out of an already detected image.
 *
 * The type is passed in rather than detected again: `detectImageType` has to run
 * first, so a caller cannot sanitize bytes under a format they are not in - the
 * sanitizer itself then insists on that format's signature and structure.
 */
export function sanitizeImage(type: ImageType, bytes: Buffer): Buffer {
  switch (type) {
    case 'jpeg':
      return sanitizeJpeg(bytes);
    case 'png':
      return sanitizePng(bytes);
    default:
      throw new DocumentIngestError();
  }
}
