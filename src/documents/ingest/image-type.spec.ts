import {
  assertClaimedTypeMatches,
  assertImageDimensions,
  assertUploadSize,
  detectImageType,
  type ClaimedType,
} from './image-type';
import {
  MAX_IMAGE_DIMENSION,
  MAX_IMAGE_PIXELS,
  MAX_UPLOAD_BYTES,
  MIN_UPLOAD_BYTES,
} from './ingest.constants';
import { DocumentIngestError } from './ingest.errors';
import { buildJpeg, buildPng } from './testing/image-fixtures';

/**
 * Files a caller might hand over hoping they pass as an image. None of them
 * starts with an image signature, and the text is filler on purpose.
 */
const NOT_AN_IMAGE: Readonly<Record<string, string>> = {
  'an executable': 'MZ\x90\x00\x03\x00\x00\x00test-only',
  'a text file': 'name,email\nsomeone,someone@example.test\n',
  'an html page': '<!doctype html><html><body>test-only</body></html>',
  'an svg drawing': '<svg xmlns="http://www.w3.org/2000/svg"><text>test-only</text></svg>',
  'a pdf document': '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n',
  'a gif image': 'GIF89a\x01\x00\x01\x00\x00\x00\x00test-only',
};

/** Claims that agree with JPEG bytes. */
const JPEG_CLAIMS: readonly ClaimedType[] = [
  {},
  { claimedExtension: 'jpg' },
  { claimedExtension: 'jpeg' },
  { claimedExtension: '.JPEG' },
  { claimedExtension: ' jpg ' },
  { claimedMime: 'image/jpeg' },
  { claimedMime: 'IMAGE/JPEG' },
  { claimedMime: 'image/jpeg; charset=binary' },
  { claimedExtension: 'jpg', claimedMime: 'image/jpeg' },
];

describe('detectImageType', () => {
  it('decides from the magic bytes', () => {
    expect(detectImageType(buildJpeg())).toBe('jpeg');
    expect(detectImageType(buildPng())).toBe('png');
  });

  it('rejects everything that is not a JPEG or a PNG', () => {
    for (const [description, content] of Object.entries(NOT_AN_IMAGE)) {
      expect(() => detectImageType(Buffer.from(content, 'latin1'))).toThrow(
        new DocumentIngestError(),
      );
      expect(description).toBeTruthy();
    }
  });

  it('rejects an empty buffer', () => {
    expect(() => detectImageType(Buffer.alloc(0))).toThrow(DocumentIngestError);
  });

  it('rejects bytes that only start like a signature', () => {
    // Four of the eight PNG bytes, then ordinary text.
    const almostPng = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      Buffer.from('test-only'),
    ]);

    expect(() => detectImageType(almostPng)).toThrow(DocumentIngestError);
  });
});

describe('assertClaimedTypeMatches', () => {
  it('accepts every claim that agrees with the bytes', () => {
    for (const claim of JPEG_CLAIMS) {
      expect(() => assertClaimedTypeMatches('jpeg', claim)).not.toThrow();
    }

    expect(() =>
      assertClaimedTypeMatches('png', { claimedExtension: 'png', claimedMime: 'image/png' }),
    ).not.toThrow();
  });

  it('rejects JPEG bytes named as a PNG', () => {
    expect(() => assertClaimedTypeMatches('jpeg', { claimedExtension: 'png' })).toThrow(
      new DocumentIngestError(),
    );
    expect(() => assertClaimedTypeMatches('jpeg', { claimedMime: 'image/png' })).toThrow(
      DocumentIngestError,
    );
  });

  it('rejects PNG bytes named as a JPEG', () => {
    expect(() => assertClaimedTypeMatches('png', { claimedExtension: 'jpeg' })).toThrow(
      DocumentIngestError,
    );
    expect(() => assertClaimedTypeMatches('png', { claimedMime: 'image/jpeg' })).toThrow(
      DocumentIngestError,
    );
  });

  it('rejects an extension or MIME type the pipeline does not ingest', () => {
    for (const extension of ['exe', 'txt', 'html', 'svg', 'pdf', 'gif']) {
      expect(() => assertClaimedTypeMatches('jpeg', { claimedExtension: extension })).toThrow(
        DocumentIngestError,
      );
      expect(() => assertClaimedTypeMatches('png', { claimedExtension: extension })).toThrow(
        DocumentIngestError,
      );
    }

    for (const claimedMime of ['application/pdf', 'text/html', 'image/svg+xml', 'image/gif']) {
      expect(() => assertClaimedTypeMatches('png', { claimedMime })).toThrow(DocumentIngestError);
    }
  });

  it('rejects when only one of the two claims is wrong', () => {
    expect(() =>
      assertClaimedTypeMatches('png', { claimedExtension: 'png', claimedMime: 'image/jpeg' }),
    ).toThrow(DocumentIngestError);
  });
});

describe('assertUploadSize', () => {
  it('accepts a size between the limits, boundaries included', () => {
    expect(() => assertUploadSize(Buffer.alloc(MIN_UPLOAD_BYTES))).not.toThrow();
    expect(() => assertUploadSize(Buffer.alloc(MAX_UPLOAD_BYTES))).not.toThrow();
    expect(() => assertUploadSize(buildJpeg())).not.toThrow();
    expect(() => assertUploadSize(buildPng())).not.toThrow();
  });

  it('rejects an empty upload', () => {
    expect(() => assertUploadSize(Buffer.alloc(0))).toThrow(DocumentIngestError);
  });

  it('rejects an upload below the minimum', () => {
    expect(() => assertUploadSize(Buffer.alloc(MIN_UPLOAD_BYTES - 1))).toThrow(DocumentIngestError);
  });

  it('rejects an upload above the maximum', () => {
    expect(() => assertUploadSize(Buffer.alloc(MAX_UPLOAD_BYTES + 1))).toThrow(DocumentIngestError);
  });

  it('decides on the length alone, so it can run before any parsing', () => {
    // A real image padded past the cap and a buffer that is not an image at all
    // are treated the same: the gate never looks at a single content byte.
    const padded = Buffer.concat([buildJpeg(), Buffer.alloc(MAX_UPLOAD_BYTES)]);

    expect(() => assertUploadSize(padded)).toThrow(DocumentIngestError);
    expect(() => assertUploadSize(Buffer.alloc(MAX_UPLOAD_BYTES + 1, 0xff))).toThrow(
      DocumentIngestError,
    );
  });
});

describe('assertImageDimensions', () => {
  it('accepts a size inside both caps, boundaries included', () => {
    expect(() => assertImageDimensions(1, 1)).not.toThrow();
    expect(() => assertImageDimensions(MAX_IMAGE_DIMENSION, 1)).not.toThrow();
    // The pixel cap is reached exactly, without either side going over.
    expect(() =>
      assertImageDimensions(MAX_IMAGE_DIMENSION, MAX_IMAGE_PIXELS / MAX_IMAGE_DIMENSION),
    ).not.toThrow();
  });

  it('rejects a side that is too long', () => {
    expect(() => assertImageDimensions(MAX_IMAGE_DIMENSION + 1, 1)).toThrow(DocumentIngestError);
    expect(() => assertImageDimensions(1, MAX_IMAGE_DIMENSION + 1)).toThrow(DocumentIngestError);
  });

  it('rejects a total pixel count that is too high', () => {
    expect(() =>
      assertImageDimensions(MAX_IMAGE_DIMENSION, MAX_IMAGE_PIXELS / MAX_IMAGE_DIMENSION + 1),
    ).toThrow(DocumentIngestError);
  });

  it('rejects a size that cannot describe an image', () => {
    for (const [width, height] of [
      [0, 10],
      [10, 0],
      [-1, 10],
      [10.5, 10],
      [Number.NaN, 10],
    ] as const) {
      expect(() => assertImageDimensions(width, height)).toThrow(DocumentIngestError);
    }
  });
});

describe('DocumentIngestError', () => {
  it('says nothing about the file it rejected', () => {
    const error = new DocumentIngestError();

    expect(error.message).toBe('Upload rejected');
    expect(error.message).not.toMatch(/\d/u);

    // The same wording whatever the reason: size, magic bytes or claims.
    const reasons = [
      () => assertUploadSize(Buffer.alloc(MAX_UPLOAD_BYTES + 1)),
      () => detectImageType(Buffer.from('test-only')),
      () => assertClaimedTypeMatches('jpeg', { claimedExtension: 'png' }),
    ];

    for (const reason of reasons) {
      expect(reason).toThrow(new DocumentIngestError());
    }
  });
});
