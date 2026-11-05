import { assertImageDimensions } from './image-type';
import { DocumentIngestError } from './ingest.errors';

/**
 * Rebuilds a JPEG from the segments a decoder actually needs.
 *
 * Everything a camera, a phone or a screenshot tool likes to attach - EXIF, XMP,
 * ICC profiles, GPS coordinates, free-text comments - travels in APP1..APP15 and
 * COM segments. They are dropped instead of copied through, so a stripped file
 * can no longer carry metadata out of the system.
 *
 * The input is read, never written: the result is a new buffer built from the
 * segments the output keeps.
 */

const MARKER_PREFIX = 0xff;
const SOI = 0xd8;
const EOI = 0xd9;
const SOS = 0xda;
const APP0 = 0xe0;
const DHT = 0xc4;
const DQT = 0xdb;
const DRI = 0xdd;

const START_OF_FRAME = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

/** Segments copied through verbatim: the ones a decoder needs to render the image. */
const KEPT = new Set([...START_OF_FRAME, DHT, DQT, DRI, SOS]);

/** `APP0` is kept only when it is the JFIF header, not a JFXX thumbnail. */
const JFIF_HEADER = Buffer.from('JFIF\0', 'latin1');

/**
 * Reads one byte, or refuses the file.
 *
 * Every offset in this file comes from a length field the file itself supplied,
 * so a read past the end is a malformed file and not a programming mistake.
 */
function byteAt(bytes: Buffer, offset: number): number {
  const byte = bytes[offset];

  if (byte === undefined) throw new DocumentIngestError();

  return byte;
}

function isJfif(payload: Buffer): boolean {
  return (
    payload.length >= JFIF_HEADER.length &&
    payload.subarray(0, JFIF_HEADER.length).equals(JFIF_HEADER)
  );
}

/**
 * Offset of the marker that ends the entropy-coded data of a scan.
 *
 * Inside the data a `FF` byte is either a stuffed literal (`FF 00`), a restart
 * marker (`FF D0`..`FF D7`), or the prefix of the next segment - which is what
 * this function returns. A `FF` with nothing usable behind it means the file was
 * cut short.
 */
function endOfScanData(bytes: Buffer, offset: number): number {
  let position = offset;

  while (position < bytes.length) {
    if (byteAt(bytes, position) !== MARKER_PREFIX) {
      position += 1;
      continue;
    }

    // Fill bytes are legal in front of a marker, so run to the marker itself.
    let next = position + 1;
    while (next < bytes.length && byteAt(bytes, next) === MARKER_PREFIX) next += 1;

    if (next >= bytes.length) throw new DocumentIngestError();

    const marker = byteAt(bytes, next);

    if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
      position = next + 1;
      continue;
    }

    return position;
  }

  throw new DocumentIngestError();
}

export function sanitizeJpeg(bytes: Buffer): Buffer {
  if (bytes.length < 4 || byteAt(bytes, 0) !== MARKER_PREFIX || byteAt(bytes, 1) !== SOI) {
    throw new DocumentIngestError();
  }

  const parts: Buffer[] = [Buffer.from([MARKER_PREFIX, SOI])];
  let offset = 2;
  let seenFrame = false;
  let seenScan = false;

  while (offset < bytes.length) {
    if (byteAt(bytes, offset) !== MARKER_PREFIX) throw new DocumentIngestError();

    // Fill bytes are legal in front of a marker; the output writes exactly one.
    while (offset < bytes.length && byteAt(bytes, offset) === MARKER_PREFIX) offset += 1;

    if (offset >= bytes.length) throw new DocumentIngestError();

    // The one `FF` the output keeps: fill bytes are dropped, the marker is not.
    const markerOffset = offset - 1;
    const marker = byteAt(bytes, offset);

    offset += 1;

    if (marker === EOI) {
      // A frame and at least one scan are what make the file an image.
      if (!seenFrame || !seenScan) throw new DocumentIngestError();
      // Nothing may follow the end of the image.
      if (offset !== bytes.length) throw new DocumentIngestError();

      parts.push(Buffer.from([MARKER_PREFIX, EOI]));

      return Buffer.concat(parts);
    }

    // `00` is a stuffed byte and `D0`..`D7` are restart markers: both only ever
    // appear inside scan data, so neither can start a segment here.
    if (marker === 0x00 || marker === 0x01 || marker === SOI) throw new DocumentIngestError();
    if (marker >= 0xd0 && marker <= 0xd7) throw new DocumentIngestError();

    if (offset + 2 > bytes.length) throw new DocumentIngestError();

    const length = bytes.readUInt16BE(offset);
    const end = offset + length;

    // A length counts itself, so anything below 2 is a lie, and one that runs
    // past the buffer is a truncated file.
    if (length < 2 || end > bytes.length) throw new DocumentIngestError();

    const payload = bytes.subarray(offset + 2, end);

    if (START_OF_FRAME.has(marker)) {
      // precision, height, width, component count, then three bytes each.
      if (payload.length < 6 || payload.length !== 6 + 3 * byteAt(payload, 5)) {
        throw new DocumentIngestError();
      }

      assertImageDimensions(payload.readUInt16BE(3), payload.readUInt16BE(1));
      seenFrame = true;
    }

    if (marker === SOS) {
      // component count, then two bytes each, then three bytes of scan setup.
      if (payload.length < 6 || payload.length !== 4 + 2 * byteAt(payload, 0)) {
        throw new DocumentIngestError();
      }

      seenScan = true;
      parts.push(bytes.subarray(markerOffset, end));

      const scanEnd = endOfScanData(bytes, end);

      parts.push(bytes.subarray(end, scanEnd));
      offset = scanEnd;
      continue;
    }

    if (KEPT.has(marker) || (marker === APP0 && isJfif(payload))) {
      parts.push(bytes.subarray(markerOffset, end));
    }

    offset = end;
  }

  // The loop left without meeting EOI: the image is incomplete.
  throw new DocumentIngestError();
}
