/**
 * The one message a rejected upload ever gets.
 *
 * It is a constant on purpose: see `DocumentIngestError`.
 */
const REJECTED = 'Upload rejected';

/**
 * The only error the ingest pipeline throws.
 *
 * Every failure - wrong size, wrong magic bytes, a name that contradicts the
 * content, a truncated or malformed file - looks identical from the outside.
 * The message never names the file, its size or the type that was detected, so
 * a caller cannot learn the limits by probing them one upload at a time.
 */
export class DocumentIngestError extends Error {
  constructor() {
    super(REJECTED);
    this.name = 'DocumentIngestError';
  }
}
