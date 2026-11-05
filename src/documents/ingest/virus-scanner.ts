/**
 * The one thing the ingest pipeline needs from an antivirus scanner.
 *
 * The contract is deliberately narrow: `scan` resolves only when the bytes are
 * clean. An infection and a scanner that cannot be reached both reject, so a
 * caller that forgets to handle one of them still refuses the upload instead of
 * letting an unscanned file through.
 */
export interface VirusScanner {
  /**
   * Scans `bytes`, resolving only on a clean verdict and rejecting with a
   * `DocumentIngestError` otherwise (infected, unavailable, timed out, garbage
   * reply - all the same error).
   */
  scan(bytes: Buffer): Promise<void>;
}
