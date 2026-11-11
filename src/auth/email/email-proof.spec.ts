import { EmailProofService } from './email-proof';
import type { ProofNonceStore } from '../otp/proof-token';

class MemoryNonceStore implements ProofNonceStore {
  readonly values = new Map<string, string>();
  async put(jti: string, value: string): Promise<boolean> {
    this.values.set(jti, value);
    return true;
  }
  async take(jti: string): Promise<string | null> {
    const value = this.values.get(jti) ?? null;
    this.values.delete(jti);
    return value;
  }
}

const KEY = 'unit-test-email-code-hmac-key-0123456789';
const EMAIL = ' User@Example.com ';

describe('EmailProofService', () => {
  it('round trips once and refuses tampering and wrong purpose', async () => {
    const store = new MemoryNonceStore();
    const service = new EmailProofService({ EMAIL_CODE_HMAC_KEY: KEY }, store);
    const proof = await service.issueEmailProof({
      email: EMAIL,
      purpose: 'register',
      nowMs: 1_000_000,
    });
    expect(
      await service.consumeEmailProof({ proof, purpose: 'login_device', nowMs: 1_000_001 }),
    ).toBeNull();
    expect(await service.consumeEmailProof({ proof, purpose: 'register', nowMs: 1_001_000 })).toBe(
      'user@example.com',
    );
    expect(
      await service.consumeEmailProof({ proof, purpose: 'register', nowMs: 1_001_000 }),
    ).toBeNull();
    expect(await service.consumeEmailProof({ proof: `${proof}x`, purpose: 'register' })).toBeNull();
  });

  it('refuses expired tokens and phone proof-shaped tokens', async () => {
    const store = new MemoryNonceStore();
    const service = new EmailProofService({ EMAIL_CODE_HMAC_KEY: KEY }, store);
    const proof = await service.issueEmailProof({
      email: 'a@example.com',
      purpose: 'login_device',
      nowMs: 1_000_000,
    });
    expect(
      await service.consumeEmailProof({ proof, purpose: 'login_device', nowMs: 1_600_001 }),
    ).toBeNull();
    expect(
      await service.consumeEmailProof({
        proof: 'eyJ2IjoyLCJwaG9uZUhhc2giOiIifQ.x',
        purpose: 'login_device',
      }),
    ).toBeNull();
  });

  it('maps nonce failures to 503', async () => {
    const store: ProofNonceStore = {
      put: async () => {
        throw new Error();
      },
      take: async () => {
        throw new Error();
      },
    };
    const service = new EmailProofService({ EMAIL_CODE_HMAC_KEY: KEY }, store);
    await expect(
      service.issueEmailProof({ email: 'a@example.com', purpose: 'register' }),
    ).rejects.toMatchObject({ status: 503 });
  });
});
