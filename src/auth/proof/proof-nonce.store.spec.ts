import {
  PROOF_NONCE_KEY_PREFIX,
  RedisProofNonceStore,
  type ProofRedisClient,
} from './proof-nonce.store';

const SUBJECT = 'athlete@example.com';
const TTL_SECONDS = 600;

function createClient(): jest.Mocked<Required<ProofRedisClient>> {
  return {
    set: jest.fn().mockResolvedValue('OK'),
    getdel: jest.fn().mockResolvedValue(SUBJECT),
    get: jest.fn().mockResolvedValue(SUBJECT),
  } as jest.Mocked<Required<ProofRedisClient>>;
}

describe('RedisProofNonceStore', () => {
  it('writes the nonce under the proof namespace with a TTL and NX', async () => {
    const client = createClient();
    const store = new RedisProofNonceStore(client);

    await expect(store.put('jti-1', SUBJECT, TTL_SECONDS)).resolves.toBe(true);
    expect(client.set).toHaveBeenCalledWith(
      `${PROOF_NONCE_KEY_PREFIX}jti-1`,
      SUBJECT,
      'EX',
      TTL_SECONDS,
      'NX',
    );
    // The subject only lives in the value, never in the key.
    expect(client.set.mock.calls[0]?.[0]).not.toContain(SUBJECT);
  });

  it('reports a refused write when the key already exists', async () => {
    const client = createClient();
    client.set.mockResolvedValue(null);

    await expect(new RedisProofNonceStore(client).put('jti-1', SUBJECT, 60)).resolves.toBe(false);
  });

  it('consumes the nonce atomically with GETDEL', async () => {
    const client = createClient();
    const store = new RedisProofNonceStore(client);

    await expect(store.take('jti-1')).resolves.toBe(SUBJECT);
    expect(client.getdel).toHaveBeenCalledWith(`${PROOF_NONCE_KEY_PREFIX}jti-1`);

    client.getdel.mockResolvedValue(null);
    await expect(store.take('jti-1')).resolves.toBeNull();
  });

  it('peeks at the nonce without spending it', async () => {
    const client = createClient();
    const store = new RedisProofNonceStore(client);

    await expect(store.get('jti-1')).resolves.toBe(SUBJECT);
    expect(client.get).toHaveBeenCalledWith(`${PROOF_NONCE_KEY_PREFIX}jti-1`);
    expect(client.getdel).not.toHaveBeenCalled();
  });

  it('fails closed when the client cannot peek', async () => {
    const store = new RedisProofNonceStore({ set: jest.fn(), getdel: jest.fn() });

    await expect(store.get('jti-1')).rejects.toThrow('nonce store cannot peek');
  });
});
