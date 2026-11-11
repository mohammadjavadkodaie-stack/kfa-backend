import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createEmailProvider, EMAIL_PROVIDER, FakeEmailProvider } from './email.provider';

describe('createEmailProvider', () => {
  it('builds the fake adapter outside production', () => {
    const provider = createEmailProvider({ NODE_ENV: 'test', EMAIL_PROVIDER: 'fake' });

    expect(provider).toBeInstanceOf(FakeEmailProvider);
    expect(provider.fixedCode).toBe('123456');
  });

  it('refuses the fake adapter in production', () => {
    expect(() => createEmailProvider({ NODE_ENV: 'production', EMAIL_PROVIDER: 'fake' })).toThrow(
      /not allowed in NODE_ENV=production/u,
    );
  });

  it('refuses a provider that is not implemented yet', () => {
    expect(() => createEmailProvider({ NODE_ENV: 'test', EMAIL_PROVIDER: 'ses' })).toThrow(
      /not implemented/u,
    );
    expect(() => createEmailProvider({ NODE_ENV: 'production', EMAIL_PROVIDER: 'ses' })).toThrow(
      /not implemented/u,
    );
  });

  it('exposes the fixed code only on the fake adapter', () => {
    expect(createEmailProvider({ NODE_ENV: 'development', EMAIL_PROVIDER: 'fake' }).fixedCode).toBe(
      '123456',
    );
    // Anything that is not the fake is refused, so no other adapter can carry a
    // static code that would shortcut verification.
    expect(() =>
      createEmailProvider({ NODE_ENV: 'development', EMAIL_PROVIDER: 'resend' }),
    ).toThrow(/not implemented/u);
  });

  it('exposes a stable Nest injection token', () => {
    expect(typeof EMAIL_PROVIDER).toBe('symbol');
    expect(EMAIL_PROVIDER.toString()).toBe('Symbol(EMAIL_PROVIDER)');
  });
});

describe('FakeEmailProvider', () => {
  it('accepts every code and resolves without sending anything', async () => {
    const provider = new FakeEmailProvider();

    await expect(
      provider.sendCode({ to: 'user@example.com', purpose: 'password_reset', code: '000000' }),
    ).resolves.toBeUndefined();
    await expect(
      provider.sendNotice({ to: 'user@example.com', kind: 'password_changed' }),
    ).resolves.toBeUndefined();
  });

  it('never writes the address or the code to the console', async () => {
    const methods = ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const;
    const spies = methods.map((method) =>
      jest.spyOn(console, method).mockImplementation(() => undefined),
    );

    try {
      const provider = new FakeEmailProvider();

      await provider.sendCode({ to: 'user@example.com', purpose: 'register', code: '123456' });
      await provider.sendNotice({ to: 'user@example.com', kind: 'new_device_login' });
    } finally {
      for (const spy of spies) spy.mockRestore();
    }

    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('keeps the adapter free of any logger', () => {
    const source = readFileSync(join(__dirname, 'email.provider.ts'), 'utf8');

    // A fake transport must stay silent: no logger import, no console fallback.
    expect(source).not.toMatch(/console\./u);
    expect(source).not.toMatch(/\blogger\b/u);
    expect(source).not.toMatch(/\bpino\b/u);
  });
});
