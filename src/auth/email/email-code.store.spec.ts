import { InMemoryEmailCodeStore } from './email-code.store';

describe('InMemoryEmailCodeStore', () => {
  let now: number;
  let store: InMemoryEmailCodeStore;

  beforeEach(() => {
    now = 1_000;
    store = new InMemoryEmailCodeStore(() => now);
  });

  it('consumes a correct code only once', async () => {
    await store.put('key', 'hash', 60);

    await expect(store.verifyAndConsume('key', 'hash', 3)).resolves.toBe('ok');
    await expect(store.verifyAndConsume('key', 'hash', 3)).resolves.toBe('missing');
  });

  it('increments attempts on wrong codes', async () => {
    await store.put('key', 'hash', 60);

    await expect(store.verifyAndConsume('key', 'wrong', 3)).resolves.toBe('wrong');
    await expect(store.verifyAndConsume('key', 'wrong', 3)).resolves.toBe('wrong');
  });

  it('returns locked_now on the maximum wrong attempt', async () => {
    await store.put('key', 'hash', 60);

    await expect(store.verifyAndConsume('key', 'wrong', 2)).resolves.toBe('wrong');
    await expect(store.verifyAndConsume('key', 'wrong', 2)).resolves.toBe('locked_now');
  });

  it('returns locked after the code has become locked', async () => {
    await store.put('key', 'hash', 60);
    await store.verifyAndConsume('key', 'wrong', 1);

    await expect(store.verifyAndConsume('key', 'hash', 1)).resolves.toBe('locked');
  });

  it('returns missing after expiry', async () => {
    await store.put('key', 'hash', 1);
    now += 1_000;

    await expect(store.verifyAndConsume('key', 'hash', 3)).resolves.toBe('missing');
  });

  it('resets attempts when replacing a code', async () => {
    await store.put('key', 'first', 60);
    await store.verifyAndConsume('key', 'wrong', 2);
    await store.put('key', 'second', 60);

    await expect(store.verifyAndConsume('key', 'second', 2)).resolves.toBe('ok');
  });

  it('keeps separate keys independent', async () => {
    await store.put('one', 'one-hash', 60);
    await store.put('two', 'two-hash', 60);

    await expect(store.verifyAndConsume('one', 'wrong', 1)).resolves.toBe('locked_now');
    await expect(store.verifyAndConsume('two', 'two-hash', 1)).resolves.toBe('ok');
  });
});
