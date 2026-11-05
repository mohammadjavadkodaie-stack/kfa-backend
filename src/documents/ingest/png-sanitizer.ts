import { assertImageDimensions } from './image-type';
import { DocumentIngestError } from './ingest.errors';

/**
 * Rebuilds a PNG from the chunks that are needed to display it.
 *
 * PNG keeps its metadata in chunks that sit next to the pixels: tEXt, zTXt and
 * iTXt for free text, eXIf for EXIF, tIME, pHYs, gAMA, iCCP and any number of
 * private chunks. All of them are dropped, and every kept chunk is written out
 * again with a freshly computed CRC.
 */

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const IHDR = 'IHDR';
const PLTE = 'PLTE';
const IDAT = 'IDAT';
const IEND = 'IEND';
const tRNS = 'tRNS';

/** Chunks copied through: the header, the palette, the pixels, transparency and the end. */
const KEPT = new Set([IHDR, PLTE, IDAT, IEND, tRNS]);

/** The header chunk is exactly this long: two 32 bit sizes and five single bytes. */
const IHDR_BYTES = 13;

/** Length, type, and CRC: what every chunk costs before its data starts. */
const CHUNK_OVERHEAD = 12;

/**
 * CRC-32 as PNG defines it, table-driven because it runs over every kept byte.
 *
 * A bad CRC means a chunk is damaged or was tampered with, so a mismatch rejects
 * the whole file rather than a single chunk.
 */
const CRC_TABLE = buildCrcTable();

function buildCrcTable(): Uint32Array {
  const table = new Uint32Array(256);

  for (let index = 0; index < 256; index += 1) {
    let value = index;

    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }

    table[index] = value >>> 0;
  }

  return table;
}

function crc32(bytes: Buffer): number {
  let crc = 0xffffffff;

  for (const byte of bytes) {
    // The index is masked to a byte, so the 256 entry table always has it.
    const entry = CRC_TABLE[(crc ^ byte) & 0xff] ?? 0;

    crc = entry ^ (crc >>> 8);
  }

  return (crc ^ 0xffffffff) >>> 0;
}

/** A chunk type is four ASCII letters; anything else cannot be a chunk. */
function isChunkType(type: Buffer): boolean {
  return type.every((byte) => (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a));
}

/** One chunk, with a CRC computed over its type and its data. */
function buildChunk(type: string, data: Buffer): Buffer {
  const typeBytes = Buffer.from(type, 'latin1');
  const header = Buffer.alloc(8);

  header.writeUInt32BE(data.length, 0);
  header.write(type, 4, 'latin1');

  const trailer = Buffer.alloc(4);

  trailer.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 0);

  return Buffer.concat([header, data, trailer]);
}

export function sanitizePng(bytes: Buffer): Buffer {
  if (
    bytes.length < SIGNATURE.length + CHUNK_OVERHEAD ||
    !bytes.subarray(0, SIGNATURE.length).equals(SIGNATURE)
  ) {
    throw new DocumentIngestError();
  }

  const parts: Buffer[] = [SIGNATURE];
  let offset = SIGNATURE.length;
  let seenHeader = false;
  let seenData = false;
  let seenEnd = false;

  while (offset < bytes.length) {
    if (offset + CHUNK_OVERHEAD > bytes.length) throw new DocumentIngestError();

    const length = bytes.readUInt32BE(offset);
    const end = offset + CHUNK_OVERHEAD + length;

    // A chunk that reaches past the buffer is a truncated file.
    if (end > bytes.length) throw new DocumentIngestError();

    const typeBytes = bytes.subarray(offset + 4, offset + 8);
    const type = typeBytes.toString('latin1');
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    const declaredCrc = bytes.readUInt32BE(offset + 8 + length);

    if (!isChunkType(typeBytes)) throw new DocumentIngestError();

    // The CRC covers the type and the data, so a flipped byte anywhere rejects.
    if (crc32(bytes.subarray(offset + 4, offset + 8 + length)) !== declaredCrc) {
      throw new DocumentIngestError();
    }

    if (!seenHeader) {
      if (type !== IHDR || length !== IHDR_BYTES) throw new DocumentIngestError();

      assertImageDimensions(data.readUInt32BE(0), data.readUInt32BE(4));
      seenHeader = true;
    }

    if (type === IDAT) seenData = true;

    if (type === IEND) {
      // The end chunk is empty, and an image without pixels is not an image.
      if (length !== 0 || !seenData) throw new DocumentIngestError();

      parts.push(buildChunk(type, data));
      offset = end;
      seenEnd = true;
      break;
    }

    if (KEPT.has(type)) parts.push(buildChunk(type, data));

    offset = end;
  }

  if (!seenHeader || !seenEnd) throw new DocumentIngestError();
  // Nothing may follow the end chunk.
  if (offset !== bytes.length) throw new DocumentIngestError();

  return Buffer.concat(parts);
}
