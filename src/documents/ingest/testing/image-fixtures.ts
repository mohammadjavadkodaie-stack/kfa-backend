/**
 * Builders for the smallest JPEG and PNG the sanitizers accept.
 *
 * Everything is assembled from bytes in code, so no binary fixture is committed
 * and nothing has to be downloaded. The strings below are filler, and the ones
 * that could look like a credential all carry "test-only": a secret scanner has
 * nothing to flag, and no value here can authenticate against anything.
 */

/** CRC-32 as PNG defines it, written out bit by bit and independently of the sanitizer. */
export function crc32(bytes: Buffer): number {
  let crc = 0xffffffff;

  for (const byte of bytes) {
    crc ^= byte;

    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) === 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }

  return (crc ^ 0xffffffff) >>> 0;
}

/** Copies a fixture and appends bytes, for the "nothing may follow the end" checks. */
export function withTrailingBytes(bytes: Buffer, extra: Buffer): Buffer {
  return Buffer.concat([bytes, extra]);
}

/** Copies a fixture and cuts it short, for the truncated-file checks. */
export function truncatedTo(bytes: Buffer, length: number): Buffer {
  return Buffer.from(bytes.subarray(0, length));
}

/**
 * One JPEG marker segment: `FF marker`, the 16 bit length and the payload.
 *
 * The length counts itself, which is what every reader of a JPEG expects.
 */
export function jpegSegment(marker: number, payload: Buffer): Buffer {
  const header = Buffer.from([0xff, marker, 0, 0]);

  header.writeUInt16BE(payload.length + 2, 2);

  return Buffer.concat([header, payload]);
}

export interface JpegOptions {
  readonly width?: number;
  readonly height?: number;
  /** Extra segments, placed directly after SOI where a real encoder puts them. */
  readonly segments?: readonly Buffer[];
}

const JPEG_SOI = Buffer.from([0xff, 0xd8]);
const JPEG_EOI = Buffer.from([0xff, 0xd9]);

const JFIF_PAYLOAD = Buffer.concat([
  Buffer.from('JFIF\0', 'latin1'),
  Buffer.from([1, 1, 0, 0, 1, 0, 1, 0, 0]),
]);

/** Precision, height, width, three components, and the sampling of each. */
function framePayload(width: number, height: number): Buffer {
  const payload = Buffer.alloc(15);

  payload[0] = 8;
  payload.writeUInt16BE(height, 1);
  payload.writeUInt16BE(width, 3);
  payload[5] = 3;
  payload.set([1, 0x11, 0], 6);
  payload.set([2, 0x11, 0], 9);
  payload.set([3, 0x11, 0], 12);

  return payload;
}

/** A one-symbol Huffman table: legal, and the smallest thing a decoder accepts. */
function huffmanPayload(): Buffer {
  return Buffer.from([0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00]);
}

/** Three components, each with the default table selectors, and a full spectral band. */
function scanPayload(): Buffer {
  return Buffer.from([3, 1, 0x00, 2, 0x00, 3, 0x00, 0, 63, 0]);
}

/** Entropy-coded data, including a stuffed `FF 00` the reader has to skip. */
function scanData(): Buffer {
  return Buffer.from([0x12, 0x34, 0xff, 0x00, 0x56, 0x78, 0x9a]);
}

function jpegParts(width: number, height: number) {
  const quantisation = Buffer.alloc(65, 0x01);

  quantisation[0] = 0x00;

  return {
    app0: jpegSegment(0xe0, JFIF_PAYLOAD),
    dqt: jpegSegment(0xdb, quantisation),
    sof: jpegSegment(0xc0, framePayload(width, height)),
    dht: jpegSegment(0xc4, huffmanPayload()),
    scan: Buffer.concat([jpegSegment(0xda, scanPayload()), scanData()]),
  };
}

/** A structurally valid baseline JPEG: SOI, APP0, DQT, SOF0, DHT, SOS, data, EOI. */
export function buildJpeg(options: JpegOptions = {}): Buffer {
  const parts = jpegParts(options.width ?? 8, options.height ?? 8);

  return Buffer.concat([
    JPEG_SOI,
    ...(options.segments ?? []),
    parts.app0,
    parts.dqt,
    parts.sof,
    parts.dht,
    parts.scan,
    JPEG_EOI,
  ]);
}

/**
 * The same image with the length field of its DQT segment replaced.
 *
 * A reader that trusts the field instead of the buffer ends up reading past the
 * file, so this is how a bad segment length is presented to the sanitizer.
 */
export function jpegWithSegmentLength(length: number): Buffer {
  const parts = jpegParts(8, 8);
  const broken = Buffer.from(parts.dqt);

  broken.writeUInt16BE(length, 2);

  return Buffer.concat([JPEG_SOI, parts.app0, broken, parts.sof, parts.dht, parts.scan, JPEG_EOI]);
}

/** APP1 with an EXIF header: where a phone camera keeps its GPS coordinates. */
export const EXIF_SEGMENT = jpegSegment(
  0xe1,
  Buffer.concat([
    Buffer.from('Exif\0\0', 'latin1'),
    Buffer.from('test-only exif: gps 0,0', 'latin1'),
  ]),
);

/** APP1 with an XMP packet. */
export const XMP_SEGMENT = jpegSegment(
  0xe1,
  Buffer.from('http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>test-only</x:xmpmeta>', 'latin1'),
);

/** APP2 with an ICC colour profile, the other thing that rides along in APPn. */
export const ICC_SEGMENT = jpegSegment(
  0xe2,
  Buffer.from('ICC_PROFILE\0test-only profile', 'latin1'),
);

/** COM: the free-text comment segment, which can hold anything at all. */
export const COMMENT_SEGMENT = jpegSegment(0xfe, Buffer.from('test-only comment', 'latin1'));

/**
 * Marker bytes of every segment in a fixture, in order.
 *
 * Written against the fixtures in this folder, which are canonical - one `FF`
 * in front of each marker - so it can stay a straight walk. It knows nothing
 * about the sanitizer's own parsing, which is the point: the tests compare the
 * two descriptions of the same file.
 */
export function jpegMarkers(bytes: Buffer): number[] {
  const markers: number[] = [];
  let offset = 2;

  while (offset + 1 < bytes.length) {
    const marker = bytes[offset + 1];

    if (bytes[offset] !== 0xff || marker === undefined) throw new Error('not a jpeg fixture');

    markers.push(marker);

    if (marker === 0xd9) return markers;

    offset += 2 + bytes.readUInt16BE(offset + 2);

    if (marker !== 0xda) continue;

    // The scan data runs to the next marker: a stuffed `FF 00` and a restart
    // marker belong to the data, anything else starts a segment.
    while (offset + 1 < bytes.length) {
      const next = bytes[offset + 1];
      const isScanData =
        bytes[offset] !== 0xff ||
        next === undefined ||
        next === 0x00 ||
        (next >= 0xd0 && next <= 0xd7);

      if (!isScanData) break;

      offset += 1;
    }
  }

  return markers;
}

export const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export interface PngChunkInput {
  readonly type: string;
  readonly data: Buffer;
  /** Overrides the computed CRC, so a test can present a chunk that fails its check. */
  readonly crc?: number;
}

/** One PNG chunk: length, type, data, and the CRC over the type and the data. */
export function pngChunk(type: string, data: Buffer, crc?: number): Buffer {
  const typeBytes = Buffer.from(type, 'latin1');
  const header = Buffer.alloc(8);

  header.writeUInt32BE(data.length, 0);
  header.write(type, 4, 'latin1');

  const trailer = Buffer.alloc(4);

  trailer.writeUInt32BE(crc ?? crc32(Buffer.concat([typeBytes, data])), 0);

  return Buffer.concat([header, data, trailer]);
}

export interface PngOptions {
  readonly width?: number;
  readonly height?: number;
  /** Extra chunks, placed between the header and the pixels, where metadata sits. */
  readonly chunks?: readonly PngChunkInput[];
  /** Leaves the end chunk out, for the "missing IEND" check. */
  readonly omitEnd?: boolean;
}

/** Width, height, then bit depth, colour type, compression, filter and interlace. */
function pngHeaderPayload(width: number, height: number): Buffer {
  const payload = Buffer.alloc(13);

  payload.writeUInt32BE(width, 0);
  payload.writeUInt32BE(height, 4);
  payload[8] = 8;
  payload[9] = 2;
  payload[10] = 0;
  payload[11] = 0;
  payload[12] = 0;

  return payload;
}

/** Stand-in for the compressed pixels; the sanitizers never inflate them. */
const PIXEL_DATA = Buffer.from(
  'test-only compressed pixels, never decoded, never inflated',
  'latin1',
);

/** A structurally valid PNG: signature, header, pixels, end. */
export function buildPng(options: PngOptions = {}): Buffer {
  const { width = 8, height = 8, chunks = [], omitEnd = false } = options;

  const parts = [
    PNG_SIGNATURE,
    pngChunk('IHDR', pngHeaderPayload(width, height)),
    ...chunks.map((chunk) => pngChunk(chunk.type, chunk.data, chunk.crc)),
    pngChunk('IDAT', PIXEL_DATA),
  ];

  if (!omitEnd) parts.push(pngChunk('IEND', Buffer.alloc(0)));

  return Buffer.concat(parts);
}

/** tEXt: a keyword and free text, which is where a caption or a name ends up. */
export const TEXT_CHUNK: PngChunkInput = {
  type: 'tEXt',
  data: Buffer.from('Comment\0test-only photo', 'latin1'),
};

/** iTXt: the international variant of the same idea. */
export const INTERNATIONAL_TEXT_CHUNK: PngChunkInput = {
  type: 'iTXt',
  data: Buffer.from('Comment\0\0\0\0\0test-only note', 'latin1'),
};

/** eXIf: EXIF in a PNG, the same profile a JPEG would carry. */
export const EXIF_CHUNK: PngChunkInput = {
  type: 'eXIf',
  data: Buffer.from('test-only exif payload', 'latin1'),
};

/** tIME: the last modification time of the image. */
export const TIME_CHUNK: PngChunkInput = {
  type: 'tIME',
  data: Buffer.from([0x07, 0xe9, 1, 1, 0, 0, 0]),
};

export interface PngChunkInfo {
  readonly type: string;
  readonly data: Buffer;
  readonly crc: number;
}

/** Every chunk of a fixture, read back with the CRC it declares. */
export function pngChunks(bytes: Buffer): PngChunkInfo[] {
  const chunks: PngChunkInfo[] = [];
  let offset = PNG_SIGNATURE.length;

  while (offset + 12 <= bytes.length) {
    const length = bytes.readUInt32BE(offset);

    chunks.push({
      type: bytes.subarray(offset + 4, offset + 8).toString('latin1'),
      data: bytes.subarray(offset + 8, offset + 8 + length),
      crc: bytes.readUInt32BE(offset + 8 + length),
    });

    offset += 12 + length;
  }

  return chunks;
}

/** The correct CRC for a chunk, recomputed here so the check does not reuse the file's own. */
export function expectedCrc(chunk: PngChunkInfo): number {
  return crc32(Buffer.concat([Buffer.from(chunk.type, 'latin1'), chunk.data]));
}
