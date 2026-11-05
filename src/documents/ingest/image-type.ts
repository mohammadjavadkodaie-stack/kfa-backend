import {
  MAX_IMAGE_DIMENSION,
  MAX_IMAGE_PIXELS,
  MAX_UPLOAD_BYTES,
  MIN_UPLOAD_BYTES,
} from './ingest.constants';
import { DocumentIngestError } from './ingest.errors';

/** The image formats the ingest pipeline understands. Nothing else is accepted. */
export type ImageType = 'jpeg' | 'png';

/**
 * What the caller says the file is. Both parts are optional and neither is
 * trusted: they only have to agree with the bytes.
 */
export interface ClaimedType {
  readonly claimedExtension?: string;
  readonly claimedMime?: string;
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** SOI plus a marker prefix: `FF D8` alone is too short to be worth matching. */
const JPEG_SIGNATURE = Buffer.from([0xff, 0xd8, 0xff]);

const EXTENSIONS: Readonly<Record<string, ImageType>> = {
  jpg: 'jpeg',
  jpeg: 'jpeg',
  png: 'png',
};

const MIME_TYPES: Readonly<Record<string, ImageType>> = {
  'image/jpeg': 'jpeg',
  'image/png': 'png',
};

function startsWith(bytes: Buffer, prefix: Buffer): boolean {
  return bytes.length >= prefix.length && bytes.subarray(0, prefix.length).equals(prefix);
}

/**
 * The size gate, and the first thing that runs.
 *
 * It only looks at the length, so it is cheap enough to sit in front of
 * everything else: an oversized upload is refused before it is parsed, hashed
 * or stored, and an empty one is refused before anything tries to read a header.
 */
export function assertUploadSize(bytes: Buffer): void {
  if (bytes.length < MIN_UPLOAD_BYTES || bytes.length > MAX_UPLOAD_BYTES) {
    throw new DocumentIngestError();
  }
}

/**
 * Decides the format from the magic bytes alone.
 *
 * The file name and the declared MIME type are never consulted here: both are
 * strings the caller chose, while the first bytes of the file are what a decoder
 * will actually act on. Anything that is not JPEG or PNG is rejected.
 */
export function detectImageType(bytes: Buffer): ImageType {
  if (startsWith(bytes, PNG_SIGNATURE)) return 'png';
  if (startsWith(bytes, JPEG_SIGNATURE)) return 'jpeg';

  throw new DocumentIngestError();
}

/** `JPG`, `.jpeg` and `jpeg` all name the same format. */
function normaliseExtension(value: string): string {
  return value.trim().toLowerCase().replace(/^\./u, '');
}

/** `image/jpeg; charset=binary` still says `image/jpeg`. */
function normaliseMime(value: string): string {
  const [essence = ''] = value.split(';');

  return essence.trim().toLowerCase();
}

/**
 * Rejects a file whose name or declared type contradicts its content.
 *
 * A missing claim is fine - there is nothing to contradict - but a claim that
 * names a format the pipeline does not ingest, or a different format than the
 * bytes, is a mismatch and the upload stops here.
 */
export function assertClaimedTypeMatches(type: ImageType, claimed: ClaimedType): void {
  const { claimedExtension, claimedMime } = claimed;

  if (claimedExtension !== undefined) {
    const extension = normaliseExtension(claimedExtension);

    if (extension !== '' && EXTENSIONS[extension] !== type) throw new DocumentIngestError();
  }

  if (claimedMime !== undefined) {
    const mime = normaliseMime(claimedMime);

    if (mime !== '' && MIME_TYPES[mime] !== type) throw new DocumentIngestError();
  }
}

/**
 * Applies the dimension caps to the header of an image.
 *
 * Both the side length and the total pixel count are checked, and the pixels
 * themselves are never decoded: the header alone says how much a decoder would
 * have to allocate, which is exactly the number that has to stay bounded.
 */
export function assertImageDimensions(width: number, height: number): void {
  if (!Number.isInteger(width) || !Number.isInteger(height)) throw new DocumentIngestError();
  if (width <= 0 || height <= 0) throw new DocumentIngestError();
  if (width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) throw new DocumentIngestError();
  if (width * height > MAX_IMAGE_PIXELS) throw new DocumentIngestError();
}
