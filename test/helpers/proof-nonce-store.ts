import type { ProofNonceStore } from '../../src/auth/proof/proof-nonce.store';

/**
 * The nonce store without Redis: the same single-use contract, per process.
 *
 * Every proof in a suite (email codes, document view links) shares it, exactly
 * like the production store, so a suite never needs a server for a flow that
 * only has to prove it spent its nonce once.
 */
export class InMemoryProofNonceStore implements ProofNonceStore {
  private readonly nonces = new Map<string, { subject: string; expiresAt: number }>();

  async put(jti: string, subject: string, ttlSeconds: number): Promise<boolean> {
    this.nonces.set(jti, { subject, expiresAt: Date.now() + ttlSeconds * 1_000 });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const stored = this.nonces.get(jti);

    this.nonces.delete(jti);

    return stored === undefined || stored.expiresAt <= Date.now() ? null : stored.subject;
  }

  async get(jti: string): Promise<string | null> {
    const stored = this.nonces.get(jti);

    return stored === undefined || stored.expiresAt <= Date.now() ? null : stored.subject;
  }

  /** Forgets every nonce, for a spec that starts from an empty store. */
  clear(): void {
    this.nonces.clear();
  }
}
