/**
 * Persistence boundary for the TOTP second factor.
 *
 * The service owns policy (enrollment, replay window, lockout) and only asks
 * for atomic primitives. Two implementations exist: the Prisma one used by the
 * API and an in-memory fake used by the unit tests.
 */

/** DI token so the Prisma implementation can be swapped for the fake. */
export const TOTP_REPOSITORY = Symbol('TOTP_REPOSITORY');

/** One credential, exactly as the service needs it. Never carries a code. */
export interface TotpCredentialRecord {
  readonly userId: string;
  /** Versioned ciphertext envelope; the plaintext secret never leaves memory. */
  readonly secretEnc: string;
  /** Null while the enrollment is still unproven. */
  readonly confirmedAt: Date | null;
  /** Highest accepted time step, used to refuse replays. */
  readonly lastUsedStep: number;
}

export interface TotpRepository {
  getCredential(userId: string): Promise<TotpCredentialRecord | null>;
  /**
   * Inserts the pending secret, or replaces the pending one of a user who has
   * not confirmed yet. False means a confirmed credential exists and a second
   * factor is already active for that account.
   */
  saveUnconfirmed(userId: string, secretEnc: string): Promise<boolean>;
  /**
   * Confirms the pending credential and replaces the user's recovery codes in
   * one transaction. False means there was no pending row to confirm.
   */
  confirm(userId: string, step: number, codeHashes: readonly string[]): Promise<boolean>;
  /**
   * Swaps a confirmed credential for its pending replacement and replaces the
   * recovery codes in one transaction. The old ciphertext is part of the
   * predicate, so a reset or a concurrent rotation wins instead of being
   * overwritten. False means nothing was swapped.
   */
  rotate(
    userId: string,
    expectedSecretEnc: string,
    nextSecretEnc: string,
    step: number,
    codeHashes: readonly string[],
  ): Promise<boolean>;
  /**
   * Single-statement replay guard: false when the row is unknown, unconfirmed
   * or already at (or past) `step`.
   */
  advanceStep(userId: string, step: number): Promise<boolean>;
  /** Single-statement single-use consume; false when nothing was updated. */
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>;
  countUnusedRecoveryCodes(userId: string): Promise<number>;
  /**
   * Removes the credential and every recovery code of one account together, for
   * the owner-initiated reset. False means the account had no credential, which
   * is the retry case and not a failure.
   */
  deleteCredential(userId: string): Promise<boolean>;
}
