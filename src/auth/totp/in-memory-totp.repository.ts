import type { TotpCredentialRecord, TotpRepository } from './totp.repository';

/**
 * In-memory `TotpRepository` for unit tests.
 *
 * It reproduces the guarantees the real repository gets from single UPDATE
 * statements - one credential per user, a monotonic step and single-use
 * recovery codes - with no `await` between the check and the write.
 */

interface FakeCredential {
  secretEnc: string;
  confirmedAt: Date | null;
  lastUsedStep: number;
}

interface FakeRecoveryCode {
  readonly codeHash: string;
  usedAt: Date | null;
}

export class InMemoryTotpRepository implements TotpRepository {
  readonly credentials = new Map<string, FakeCredential>();
  readonly recoveryCodes = new Map<string, FakeRecoveryCode[]>();

  async getCredential(userId: string): Promise<TotpCredentialRecord | null> {
    const stored = this.credentials.get(userId);

    return stored === undefined ? null : { userId, ...stored };
  }

  async saveUnconfirmed(userId: string, secretEnc: string): Promise<boolean> {
    const stored = this.credentials.get(userId);

    if (stored !== undefined && stored.confirmedAt !== null) return false;

    this.credentials.set(userId, { secretEnc, confirmedAt: null, lastUsedStep: 0 });

    return true;
  }

  async confirm(userId: string, step: number, codeHashes: readonly string[]): Promise<boolean> {
    const stored = this.credentials.get(userId);

    if (stored === undefined || stored.confirmedAt !== null) return false;

    stored.confirmedAt = new Date();
    stored.lastUsedStep = step;
    this.recoveryCodes.set(
      userId,
      codeHashes.map((codeHash) => ({ codeHash, usedAt: null })),
    );

    return true;
  }

  /**
   * The check and the swap share one synchronous turn, so a reader never sees
   * the new secret with the old recovery codes (or the other way round).
   */
  async rotate(
    userId: string,
    expectedSecretEnc: string,
    nextSecretEnc: string,
    step: number,
    codeHashes: readonly string[],
  ): Promise<boolean> {
    const stored = this.credentials.get(userId);

    if (stored === undefined || stored.confirmedAt === null) return false;
    if (stored.secretEnc !== expectedSecretEnc) return false;

    stored.secretEnc = nextSecretEnc;
    stored.confirmedAt = new Date();
    stored.lastUsedStep = step;
    this.recoveryCodes.set(
      userId,
      codeHashes.map((codeHash) => ({ codeHash, usedAt: null })),
    );

    return true;
  }

  async advanceStep(userId: string, step: number): Promise<boolean> {
    const stored = this.credentials.get(userId);

    if (stored === undefined || stored.confirmedAt === null || stored.lastUsedStep >= step) {
      return false;
    }

    stored.lastUsedStep = step;

    return true;
  }

  async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
    const stored = this.recoveryCodes
      .get(userId)
      ?.find((candidate) => candidate.codeHash === codeHash && candidate.usedAt === null);

    if (stored === undefined) return false;

    stored.usedAt = new Date();

    return true;
  }

  async countUnusedRecoveryCodes(userId: string): Promise<number> {
    return (this.recoveryCodes.get(userId) ?? []).filter((code) => code.usedAt === null).length;
  }

  /** No `await` between the two removals, so a reader never sees half a reset. */
  async deleteCredential(userId: string): Promise<boolean> {
    const removed = this.credentials.delete(userId);

    this.recoveryCodes.delete(userId);

    return removed;
  }
}
