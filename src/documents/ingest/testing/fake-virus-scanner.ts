import { DocumentIngestError } from '../ingest.errors';
import type { VirusScanner } from '../virus-scanner';

/**
 * How the fake scanner answers.
 *
 * `infected` and `failing` are two different stories that end in the same
 * rejection, which is exactly what the real client does: a test can pick either
 * one and the assertion stays the same.
 */
export type FakeScannerMode = 'clean' | 'infected' | 'failing';

/**
 * A scanner under the test's control.
 *
 * It keeps a copy of every buffer it was handed, so a test can assert what was
 * really scanned - that is how "the scanner sees the sanitized bytes" is checked
 * without a daemon. The copies also keep a later in-place change of the input
 * from rewriting the record.
 */
export class FakeVirusScanner implements VirusScanner {
  readonly received: Buffer[] = [];
  private mode: FakeScannerMode;

  constructor(mode: FakeScannerMode = 'clean') {
    this.mode = mode;
  }

  /** Changes the answer of a scanner that is already in use. */
  behave(mode: FakeScannerMode): void {
    this.mode = mode;
  }

  async scan(bytes: Buffer): Promise<void> {
    this.received.push(Buffer.from(bytes));

    if (this.mode === 'clean') return;

    // An infection and an unreachable scanner are one error, on purpose.
    throw new DocumentIngestError();
  }
}
