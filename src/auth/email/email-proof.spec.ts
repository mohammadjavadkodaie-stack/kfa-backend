import { ServiceUnavailableException } from '@nestjs/common';
import { EmailProofService } from './email-proof';
import { ProofTokenService, type ProofNonceStore } from '../otp/proof-token';

class MemoryNonceStore implements ProofNonceStore {
  readonly values = new Map<string, string>();
  failPut = false;
  failTake = false;
  async put(jti: string, value: string): Promise<boolean> {
    if (this.failPut) throw new Error('nonce store down');
    this.values.set(jti, value);
    return true;
  }
  async take(jti: string): Promise<string | null> {
    if (this.failTake) throw new Error('nonce store down');
    const value = this.values.get(jti) ?? null;
    this.values.delete(jti);
    return value;
  }
}

const KEY = 'unit-test-email-code-hmac-key-0123456789';
const PHONE_SECRET = 'unit-test-otp-proof-secret-0123456789abcdef';
const EMAIL = ' User@Example.com ';
const NOW = 1_000_000;

function createService(store: ProofNonceStore = new MemoryNonceStore()): EmailProofService {
  return new EmailProofService({ EMAIL_CODE_HMAC_KEY: KEY }, store);
}

function split(proof: string): [string, string] {
  return proof.split('.') as [string, string];
}

function decodePayload(proof: string): Record<string, unknown> {
  const [payload] = split(proof);
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

function issue(service: EmailProofService, purpose: 'register' | 'login_device' = 'register') {
  return service.issueEmailProof({ email: EMAIL, purpose, nowMs: NOW });
}

describe('EmailProofService', () => {
  it('round trips an issued proof to the normalized email', async () => {
    const service = createService();
    const proof = await issue(service);

    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 1_000 }),
    ).resolves.toBe('user@example.com');
  });

  it('consumes a proof exactly once', async () => {
    const service = createService();
    const proof = await issue(service);

    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 1_000 }),
    ).resolves.toBe('user@example.com');
    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 1_000 }),
    ).resolves.toBeNull();
  });

  it('refuses a tampered payload', async () => {
    const service = createService();
    const proof = await issue(service);
    const [payload, signature] = split(proof);
    const decoded = decodePayload(proof);
    const forged = Buffer.from(
      JSON.stringify({ ...decoded, purpose: 'password_reset' }),
      'utf8',
    ).toString('base64url');

    expect(forged).not.toBe(payload);
    await expect(
      service.consumeEmailProof({
        proof: `${forged}.${signature}`,
        purpose: 'password_reset',
        nowMs: NOW + 1_000,
      }),
    ).resolves.toBeNull();
  });

  it('refuses a tampered signature', async () => {
    const service = createService();
    const proof = await issue(service);
    const [payload, signature] = split(proof);
    const flipped = `${signature.charAt(0) === 'A' ? 'B' : 'A'}${signature.slice(1)}`;

    await expect(
      service.consumeEmailProof({ proof: `${payload}.${flipped}`, purpose: 'register' }),
    ).resolves.toBeNull();
    // A truncated signature is rejected on length alone, before any comparison.
    await expect(
      service.consumeEmailProof({
        proof: `${payload}.${signature.slice(0, -4)}`,
        purpose: 'register',
      }),
    ).resolves.toBeNull();
  });

  it('refuses a proof issued for a different purpose', async () => {
    const service = createService();
    const proof = await issue(service, 'register');

    await expect(
      service.consumeEmailProof({ proof, purpose: 'login_device', nowMs: NOW + 1_000 }),
    ).resolves.toBeNull();
  });

  it('refuses an expired proof', async () => {
    const service = createService();
    const proof = await issue(service);

    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 600_001 }),
    ).resolves.toBeNull();
  });

  it('refuses a token whose nonce belongs to a different email', async () => {
    const store = new MemoryNonceStore();
    const service = createService(store);
    const proof = await issue(service);
    const jti = decodePayload(proof).jti as string;
    store.values.set(jti, 'other@example.com');

    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 1_000 }),
    ).resolves.toBeNull();
  });

  it('refuses a legacy phone proof token', async () => {
    const phoneProof = new ProofTokenService(
      { OTP_PROOF_SECRET: PHONE_SECRET },
      new MemoryNonceStore(),
    );
    const phoneToken = await phoneProof.issue('+14155552671', 'register', NOW);

    await expect(
      createService().consumeEmailProof({ proof: phoneToken, purpose: 'register' }),
    ).resolves.toBeNull();
  });

  it('is refused by the phone verifier', async () => {
    const phoneProof = new ProofTokenService(
      { OTP_PROOF_SECRET: PHONE_SECRET },
      new MemoryNonceStore(),
    );
    const emailToken = await issue(createService());

    await expect(
      phoneProof.verifyAndConsumeProof(emailToken, 'register', NOW + 1_000),
    ).resolves.toBeNull();
  });

  it('maps nonce failures to a generic 503', async () => {
    const store = new MemoryNonceStore();
    const service = createService(store);
    const proof = await issue(service);
    store.failTake = true;

    await expect(
      service.consumeEmailProof({ proof, purpose: 'register', nowMs: NOW + 1_000 }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it('fails closed with 503 when the HMAC key is missing', async () => {
    const service = new EmailProofService(
      { EMAIL_CODE_HMAC_KEY: undefined },
      new MemoryNonceStore(),
    );

    await expect(issue(service)).rejects.toMatchObject({ status: 503 });
    await expect(
      service.consumeEmailProof({ proof: 'a.b', purpose: 'register' }),
    ).rejects.toMatchObject({ status: 503 });
  });
});
