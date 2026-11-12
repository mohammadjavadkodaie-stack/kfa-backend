import { randomBytes, scrypt } from 'node:crypto';
import {
  MAX_CONCURRENT_HASHES,
  MAX_HASH_QUEUE,
  PasswordBusyError,
  PasswordService,
  PasswordTooLongError,
  ScryptSemaphore,
} from './password.service';

const PASSWORD = 'correct horse battery staple';
const NON_LATIN = 'Пароль-это-длинная-фраза';
const TIMEOUT = 30_000;

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => {
    resolve = () => settle();
  });
  return { promise, resolve };
}

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Builds a stored value for arbitrary parameters, bypassing the service's own defaults. */
function storedWith(password: string, n: number, r: number, p: number): Promise<string> {
  const salt = randomBytes(16);
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 32, { N: n, r, p, maxmem: 268_435_456 }, (error, key) => {
      if (error) {
        reject(error);
        return;
      }
      const params = `${n},${r},${p}`;
      resolve(`scrypt$v1$${params}$${salt.toString('base64url')}$${key.toString('base64url')}`);
    });
  });
}

describe('PasswordService', () => {
  const service = new PasswordService();
  let stored: string;

  beforeAll(async () => {
    stored = await service.hash(PASSWORD);
  }, TIMEOUT);

  it('stores the documented format well inside the column CHECK', () => {
    expect(stored).toMatch(/^scrypt\$v1\$65536,8,2\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/u);
    expect(stored.length).toBeGreaterThanOrEqual(20);
    expect(stored.length).toBeLessThanOrEqual(200);
  });

  it(
    'salts every hash',
    async () => {
      const again = await service.hash(PASSWORD);
      expect(again).not.toBe(stored);
      await expect(service.verify(PASSWORD, again)).resolves.toBe(true);
    },
    TIMEOUT,
  );

  it(
    'verifies the right password and rejects near misses',
    async () => {
      await expect(service.verify(PASSWORD, stored)).resolves.toBe(true);
      await expect(service.verify('Correct horse battery staple', stored)).resolves.toBe(false);
      await expect(service.verify(`${PASSWORD} `, stored)).resolves.toBe(false);
    },
    TIMEOUT,
  );

  it(
    'round-trips a non-Latin password',
    async () => {
      const hashed = await service.hash(NON_LATIN);
      await expect(service.verify(NON_LATIN, hashed)).resolves.toBe(true);
    },
    TIMEOUT,
  );

  it(
    'normalises Unicode before hashing, so equivalent forms verify',
    async () => {
      const hashed = await service.hash('ﬁ-passphrase-2026');
      await expect(service.verify('fi-passphrase-2026', hashed)).resolves.toBe(true);
    },
    TIMEOUT,
  );

  it(
    'refuses oversized input before it reaches scrypt',
    async () => {
      await expect(service.hash('a'.repeat(129))).rejects.toBeInstanceOf(PasswordTooLongError);
      await expect(service.hash('a'.repeat(128))).resolves.toMatch(/^scrypt\$v1\$/u);
      await expect(service.verify('a'.repeat(129), stored)).resolves.toBe(false);
    },
    TIMEOUT,
  );

  it('refuses non-string input', async () => {
    await expect(service.hash(42 as unknown as string)).rejects.toBeInstanceOf(TypeError);
    await expect(service.verify(42, stored)).resolves.toBe(false);
    await expect(service.verify(undefined, stored)).resolves.toBe(false);
  });

  it(
    'returns false instead of throwing for malformed stored values',
    async () => {
      const [, version, params, salt, key] = stored.split('$') as [
        string,
        string,
        string,
        string,
        string,
      ];
      const flippedKey = `${key[0] === 'A' ? 'B' : 'A'}${key.slice(1)}`;
      const malformed: unknown[] = [
        undefined,
        null,
        42,
        {},
        '',
        'garbage',
        `bcrypt$${version}$${params}$${salt}$${key}`,
        `scrypt$v2$${params}$${salt}$${key}`,
        `scrypt$v1$${params}$${salt}`,
        `scrypt$v1$${params}$${salt}$${key}$extra`,
        `scrypt$v1$${params}$${salt}$`,
        `scrypt$v1$2048,8,1$${salt}$${key}`,
        `scrypt$v1$2097152,8,1$${salt}$${key}`,
        `scrypt$v1$65537,8,1$${salt}$${key}`,
        `scrypt$v1$65536,4,1$${salt}$${key}`,
        `scrypt$v1$65536,16,1$${salt}$${key}`,
        `scrypt$v1$65536,8,0$${salt}$${key}`,
        `scrypt$v1$65536,8,5$${salt}$${key}`,
        `scrypt$v1$65536;8;2$${salt}$${key}`,
        `scrypt$v1$${params}$${salt}$${key.slice(0, 20)}`,
        `scrypt$v1$${params}$${salt.slice(0, 10)}$${key}`,
        `scrypt$v1$${params}$${salt}$${flippedKey}`,
        `scrypt$v1$${params}$${salt}!$${key}`,
      ];

      for (const value of malformed) {
        await expect(service.verify(PASSWORD, value)).resolves.toBe(false);
      }
    },
    TIMEOUT,
  );

  it(
    'honours stored parameters within bounds and flags them for rehash',
    async () => {
      const legacy = await storedWith(PASSWORD, 2 ** 14, 8, 1);
      await expect(service.verify(PASSWORD, legacy)).resolves.toBe(true);
      expect(service.needsRehash(legacy)).toBe(true);
    },
    TIMEOUT,
  );

  it('does not ask for a rehash when the parameters already match', () => {
    expect(service.needsRehash(stored)).toBe(false);
    expect(service.needsRehash('garbage')).toBe(true);
    expect(service.needsRehash(undefined)).toBe(true);
  });

  it(
    'spends a derivation on the dummy hash and always answers false',
    async () => {
      await expect(service.verifyDummy(PASSWORD)).resolves.toBe(false);
      await expect(service.verifyDummy('')).resolves.toBe(false);
    },
    TIMEOUT,
  );

  it(
    'queues concurrent verifications instead of dropping them',
    async () => {
      const results = await Promise.all(
        Array.from({ length: MAX_CONCURRENT_HASHES + 2 }, () => service.verify(PASSWORD, stored)),
      );
      expect(results).toEqual(new Array(MAX_CONCURRENT_HASHES + 2).fill(true));
    },
    TIMEOUT,
  );
});

describe('ScryptSemaphore', () => {
  it('defaults to three in flight and a fifty-deep queue', () => {
    const semaphore = new ScryptSemaphore();
    expect(MAX_CONCURRENT_HASHES).toBe(3);
    expect(MAX_HASH_QUEUE).toBe(50);
    expect(semaphore.inFlight).toBe(0);
    expect(semaphore.queued).toBe(0);
  });

  it('caps concurrency and hands a freed slot straight to the next waiter', async () => {
    const semaphore = new ScryptSemaphore(2, 4);
    const gates = [deferred(), deferred(), deferred()];
    const started: number[] = [];
    const runs = gates.map((gate, index) =>
      semaphore.run(async () => {
        started.push(index);
        await gate.promise;
        return index;
      }),
    );

    await flush();
    expect(started).toEqual([0, 1]);
    expect(semaphore.inFlight).toBe(2);
    expect(semaphore.queued).toBe(1);

    gates[0]?.resolve();
    await flush();
    expect(started).toEqual([0, 1, 2]);
    expect(semaphore.inFlight).toBe(2);
    expect(semaphore.queued).toBe(0);

    gates[1]?.resolve();
    gates[2]?.resolve();
    await expect(Promise.all(runs)).resolves.toEqual([0, 1, 2]);
    expect(semaphore.inFlight).toBe(0);
  });

  it('sheds load with PasswordBusyError once the queue is full', async () => {
    const semaphore = new ScryptSemaphore(1, 2);
    const gate = deferred();
    const holding = semaphore.run(async () => {
      await gate.promise;
      return 'held';
    });
    const queued = [semaphore.run(async () => 'first'), semaphore.run(async () => 'second')];

    await flush();
    expect(semaphore.inFlight).toBe(1);
    expect(semaphore.queued).toBe(2);

    await expect(semaphore.run(async () => 'third')).rejects.toBeInstanceOf(PasswordBusyError);
    expect(new PasswordBusyError().getStatus()).toBe(503);
    expect(semaphore.inFlight).toBe(1);
    expect(semaphore.queued).toBe(2);

    gate.resolve();
    await expect(Promise.all([holding, ...queued])).resolves.toEqual(['held', 'first', 'second']);
    expect(semaphore.inFlight).toBe(0);
    expect(semaphore.queued).toBe(0);
  });

  it('releases the slot when the work rejects', async () => {
    const semaphore = new ScryptSemaphore(1, 1);
    await expect(
      semaphore.run(async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(semaphore.inFlight).toBe(0);
    await expect(semaphore.run(async () => 'ok')).resolves.toBe('ok');
  });
});
