import { ServiceUnavailableException } from '@nestjs/common';
import {
  PROOF_NONCE_KEY_PREFIX,
  PROOF_TTL_SECONDS,
  ProofTokenService,
  RedisProofNonceStore,
  type ProofNonceStore,
} from './proof-token';

const SECRET = 'unit-test-otp-proof-secret-0123456789abcdef';
const PHONE = '+14155552671';
const NOW = 1_700_000_000_000;

/** Minimal in-memory stand-in for the Redis nonce store. */
class MemoryNonceStore implements ProofNonceStore {
  readonly entries = new Map<string, string>();
  putFailure = false;
  takeFailure = false;

  put(jti: string, phoneE164: string, _ttlSeconds: number): Promise<boolean> {
    if (this.putFailure) return Promise.reject(new Error('redis down'));

    if (this.entries.has(jti)) return Promise.resolve(false);

    this.entries.set(jti, phoneE164);

    return Promise.resolve(true);
  }

  take(jti: string): Promise<string | null> {
    if (this.takeFailure) return Promise.reject(new Error('redis down'));

    const value = this.entries.get(jti) ?? null;
    this.entries.delete(jti);

    return Promise.resolve(value);
  }

  remaining(): number {
    return this.entries.size;
  }

  has(jti: string): boolean {
    return this.entries.has(jti);
  }
}

function createService(): { service: ProofTokenService; store: MemoryNonceStore } {
  const store = new MemoryNonceStore();

  return { service: new ProofTokenService({ OTP_PROOF_SECRET: SECRET }, store), store };
}

/** Rebuilds a token from a modified payload, keeping the original signature. */
function tamperPayload(token: string, mutate: (payload: Record<string, unknown>) => void): string {
  const [payloadSegment, signatureSegment] = token.split('.') as [string, string];
  const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;

  mutate(payload);

  return `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${signatureSegment}`;
}

describe('ProofTokenService', () => {
  it('issues a proof that resolves to the normalized phone exactly once', async () => {
    const { service, store } = createService();

    const proof = await service.issue(PHONE, NOW);

    expect(typeof proof).toBe('string');
    expect(store.remaining()).toBe(1);

    await expect(service.verifyAndConsumeProof(proof, NOW + 1_000)).resolves.toBe(PHONE);
    // The nonce is gone, so the same token can never be accepted twice.
    await expect(service.verifyAndConsumeProof(proof, NOW + 1_000)).resolves.toBeNull();
    expect(store.remaining()).toBe(0);
  });

  it('never embeds the raw phone in the token', async () => {
    const { service } = createService();

    const proof = await service.issue(PHONE, NOW);
    const decoded = Buffer.from(proof.split('.')[0] as string, 'base64url').toString('utf8');

    expect(proof).not.toContain(PHONE);
    expect(proof).not.toContain('4155552671');
    expect(decoded).not.toContain(PHONE);
    expect(JSON.parse(decoded)).toMatchObject({
      v: 1,
      phoneHash: expect.stringMatching(/^[0-9a-f]{64}$/) as string,
      exp: Math.floor(NOW / 1_000) + PROOF_TTL_SECONDS,
    });
  });

  it('rejects a token signed with a different secret', async () => {
    const issuer = createService();
    const verifier = new ProofTokenService(
      { OTP_PROOF_SECRET: 'another-unit-test-proof-secret-0123456789' },
      issuer.store,
    );

    const proof = await issuer.service.issue(PHONE, NOW);

    await expect(verifier.verifyAndConsumeProof(proof, NOW + 1_000)).resolves.toBeNull();
  });

  it('rejects a payload modified after signing', async () => {
    const { service } = createService();

    const proof = await service.issue(PHONE, NOW);
    const extended = tamperPayload(proof, (payload) => {
      payload.exp = Number(payload.exp) + 3_600;
    });

    await expect(service.verifyAndConsumeProof(extended, NOW + 1_000)).resolves.toBeNull();
    // A refused token must not burn the nonce of the genuine one.
    await expect(service.verifyAndConsumeProof(proof, NOW + 1_000)).resolves.toBe(PHONE);
  });

  it('rejects an expired token without consuming the nonce', async () => {
    const { service, store } = createService();

    const proof = await service.issue(PHONE, NOW);
    const [payloadSegment] = proof.split('.') as [string];
    const { jti } = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as {
      jti: string;
    };

    expect(store.has(jti)).toBe(true);
    await expect(
      service.verifyAndConsumeProof(proof, NOW + PROOF_TTL_SECONDS * 1_000),
    ).resolves.toBeNull();
    expect(store.has(jti)).toBe(true);
    // Still accepted one millisecond before the boundary.
    await expect(
      service.verifyAndConsumeProof(proof, NOW + PROOF_TTL_SECONDS * 1_000 - 1),
    ).resolves.toBe(PHONE);
  });

  it('rejects a nonce bound to a different phone (hash mismatch)', async () => {
    const { service, store } = createService();

    const proof = await service.issue(PHONE, NOW);

    // Simulate a corrupted store: the nonce now points at another number.
    for (const jti of store.entries.keys()) {
      store.entries.set(jti, '+14155550000');
    }

    await expect(service.verifyAndConsumeProof(proof, NOW + 1_000)).resolves.toBeNull();
  });

  it.each([
    ['an empty string', ''],
    ['a token without a separator', 'not-a-token'],
    ['a token with too many segments', 'a.b.c'],
    ['a non base64 payload', '!!!!.????'],
    ['an oversized token', `${'a'.repeat(4096)}.b`],
    ['a JSON payload that is not a proof', `${Buffer.from('{"v":2}').toString('base64url')}.abc`],
    ['a wrong payload type', 42],
    ['null', null],
  ])('returns null for %s', async (_label, token) => {
    const { service } = createService();

    await expect(service.verifyAndConsumeProof(token, NOW)).resolves.toBeNull();
  });

  it('rejects a signature that is not 32 bytes', async () => {
    const { service } = createService();

    const proof = await service.issue(PHONE, NOW);
    const [payloadSegment] = proof.split('.') as [string];
    const short = Buffer.from('short').toString('base64url');

    await expect(
      service.verifyAndConsumeProof(`${payloadSegment}.${short}`, NOW),
    ).resolves.toBeNull();
  });

  it('fails closed without a secret', async () => {
    const service = new ProofTokenService({ OTP_PROOF_SECRET: undefined }, new MemoryNonceStore());

    await expect(service.issue(PHONE, NOW)).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(service.verifyAndConsumeProof('a.b', NOW)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('fails closed without a nonce store', async () => {
    const service = new ProofTokenService({ OTP_PROOF_SECRET: SECRET }, null);

    await expect(service.issue(PHONE, NOW)).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(service.verifyAndConsumeProof('a.b', NOW)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('fails closed with a generic error when the store is unreachable', async () => {
    const { service, store } = createService();

    store.putFailure = true;
    const issueError = await service.issue(PHONE, NOW).catch((error: unknown) => error);

    expect(issueError).toBeInstanceOf(ServiceUnavailableException);
    expect((issueError as Error).message).toBe('Service Unavailable');

    store.putFailure = false;
    const proof = await service.issue(PHONE, NOW);
    store.takeFailure = true;

    await expect(service.verifyAndConsumeProof(proof, NOW)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('refuses to reuse a nonce that already exists', async () => {
    const store = new MemoryNonceStore();
    const service = new ProofTokenService(
      { OTP_PROOF_SECRET: SECRET },
      {
        put: () => Promise.resolve(false),
        take: (jti: string) => store.take(jti),
      },
    );

    await expect(service.issue(PHONE, NOW)).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});

describe('RedisProofNonceStore', () => {
  function createClient() {
    return {
      set: jest.fn().mockResolvedValue('OK'),
      getdel: jest.fn().mockResolvedValue(PHONE),
    };
  }

  it('writes the nonce under the proof namespace with a TTL and NX', async () => {
    const client = createClient();
    const store = new RedisProofNonceStore(client);

    await expect(store.put('jti-1', PHONE, PROOF_TTL_SECONDS)).resolves.toBe(true);
    expect(client.set).toHaveBeenCalledWith(
      `${PROOF_NONCE_KEY_PREFIX}jti-1`,
      PHONE,
      'EX',
      PROOF_TTL_SECONDS,
      'NX',
    );
    // The raw phone only lives in the value, never in the key.
    expect(client.set.mock.calls[0]?.[0]).not.toContain('4155552671');
  });

  it('reports a refused write when the key already exists', async () => {
    const client = createClient();
    client.set.mockResolvedValue(null);

    await expect(new RedisProofNonceStore(client).put('jti-1', PHONE, 60)).resolves.toBe(false);
  });

  it('consumes the nonce atomically with GETDEL', async () => {
    const client = createClient();
    const store = new RedisProofNonceStore(client);

    await expect(store.take('jti-1')).resolves.toBe(PHONE);
    expect(client.getdel).toHaveBeenCalledWith(`${PROOF_NONCE_KEY_PREFIX}jti-1`);

    client.getdel.mockResolvedValue(null);
    await expect(store.take('jti-1')).resolves.toBeNull();
  });
});
