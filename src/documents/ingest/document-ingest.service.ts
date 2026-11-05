/**
 * The ingest pipeline: from an untrusted upload to bytes that are safe to keep.
 *
 * What it does, in this order - and the order is the contract:
 *
 *   1. refuse anything outside the size window, before a byte is parsed;
 *   2. decide the format from the magic bytes, never from the file name;
 *   3. refuse a name or a declared type that contradicts those bytes;
 *   4. strip every piece of metadata, which is where GPS coordinates, device
 *      names and comments hide;
 *   5. scan the stripped bytes, and stop unless the scanner says they are clean;
 *   6. hand back the stripped bytes with their type and their SHA-256.
 *
 * Encryption and storage are deliberately not here (stage 4.3b): this service
 * answers "may this file be kept, and as what", and nothing else.
 */

import { createHash } from 'node:crypto';
import type { Env } from '../../config/env';
import { ClamdScanner } from './clamd-scanner';
import {
  assertClaimedTypeMatches,
  assertUploadSize,
  detectImageType,
  type ClaimedType,
  type ImageType,
} from './image-type';
import { sanitizeImage } from './image-sanitizer';
import { DocumentIngestError } from './ingest.errors';
import type { VirusScanner } from './virus-scanner';

/** What a caller hands over: the bytes, and optionally what it claims they are. */
export interface IngestRequest extends ClaimedType {
  readonly bytes: Buffer;
}

/** What the pipeline hands back. */
export interface IngestedDocument {
  /** Metadata-stripped bytes: these, and only these, may be encrypted and stored. */
  readonly bytes: Buffer;
  readonly type: ImageType;
  /** Hex SHA-256 of `bytes` - the sanitized output, not the upload. */
  readonly sha256: string;
}

export class DocumentIngestService {
  /** `null` means nothing was injected and nothing is configured: every upload is refused. */
  private readonly scanner: VirusScanner | null;

  constructor(scanner?: VirusScanner | null) {
    this.scanner = scanner ?? null;
  }

  /**
   * Builds the service from the validated environment.
   *
   * With CLAMAV_HOST and CLAMAV_PORT set, the daemon is used; without them the
   * service is built with no scanner and refuses every upload. A deployment that
   * has not configured a scanner therefore fails closed instead of storing
   * unscanned files.
   */
  static fromEnv(env: Pick<Env, 'CLAMAV_HOST' | 'CLAMAV_PORT'>): DocumentIngestService {
    const { CLAMAV_HOST: host, CLAMAV_PORT: port } = env;

    if (host === undefined || port === undefined) return new DocumentIngestService();

    return new DocumentIngestService(new ClamdScanner(host, port));
  }

  /** Runs the pipeline; every failure is a `DocumentIngestError`. */
  async process(request: IngestRequest): Promise<IngestedDocument> {
    const { bytes, claimedExtension, claimedMime } = request;

    // 1. Size first: an oversized or empty upload is refused before anything
    //    tries to read a header.
    assertUploadSize(bytes);

    // 2 and 3. The bytes decide the format; the claims only have to agree.
    const type = detectImageType(bytes);

    assertClaimedTypeMatches(type, { claimedExtension, claimedMime });

    // 4. A fresh buffer: the input is read, never written.
    const sanitized = sanitizeImage(type, bytes);

    // 5. The scan runs on what would be stored, not on the upload: metadata that
    //    was stripped cannot carry a payload past the scanner, and the scanner
    //    cannot reject a file for something the pipeline drops anyway.
    const scanner = this.requireScanner();

    await scanner.scan(sanitized);

    // 6. The digest is taken after sanitizing, so it identifies the stored bytes
    //    and two uploads that differ only in metadata hash the same.
    return {
      bytes: sanitized,
      type,
      sha256: createHash('sha256').update(sanitized).digest('hex'),
    };
  }

  /** Fail closed: no scanner, no ingest. */
  private requireScanner(): VirusScanner {
    if (this.scanner === null) throw new DocumentIngestError();

    return this.scanner;
  }
}
