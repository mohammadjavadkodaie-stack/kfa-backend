import { loadEnv } from '../../config/env';
import { createCaptchaProvider, FakeCaptchaProvider } from './captcha.provider';
import {
  TURNSTILE_MAX_TOKEN_LENGTH,
  TURNSTILE_VERIFY_URL,
  TurnstileCaptchaProvider,
  type TurnstileProviderOptions,
} from './turnstile.provider';

const SECRET = 'turnstile-test-secret-0123456789';
const TOKEN = 'turnstile-response-token-abc';
const IP = '203.0.113.7';

/** Minimal development environment: the captcha key is absent, so it defaults. */
const DEV_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: 'development',
  APP_ORIGINS: 'http://localhost:3000',
  DATABASE_URL: 'postgresql://kfa_app:dev-secret@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
  ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
  DOCUMENT_VIEW_TOKEN_SECRET: 'unit-test-view-token-secret-0123456789abcdef',
  EMAIL_CODE_HMAC_KEY: 'unit-test-email-code-hmac-key-0123456789',
};

/** A production environment that satisfies every production-only rule. */
const PROD_ENV: NodeJS.ProcessEnv = {
  ...DEV_ENV,
  NODE_ENV: 'production',
  APP_ORIGINS: 'https://app.example',
  DATABASE_URL: 'postgresql://kfa_app:app-secret@db.internal:5432/kfa?sslmode=require',
  REDIS_URL: 'rediss://:prod-only-redis-password@redis.internal:6380/0',
  TOTP_ENC_KEY: 'a2ZhLXVuaXQtdGVzdC10b3RwLWVuYy1rZXktMTIzNDU',
  DOCUMENT_MASTER_KEY: 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=',
  CAPTCHA_PROVIDER: 'turnstile',
  TURNSTILE_SECRET_KEY: 'unit-test-turnstile-secret-0123456789',
  TURNSTILE_EXPECTED_HOSTNAME: 'app.example',
  EMAIL_PROVIDER: 'resend',
  RESEND_API_KEY: 'test-resend-api-key',
  EMAIL_FROM: 'KFA <no-reply@example.com>',
  // Required for the nightly encrypted backup (base64url of exactly 32 bytes).
  BACKUP_ENCRYPTION_KEY: 'a2ZhLXRlc3Qtb25seS1iYWNrdXAtZW5jLWtleS0wMDE',
  BACKUP_NOTIFY_EMAIL: 'owner@example.com',
  BACKUP_NOTIFY_EMAIL_EMERGENCY: 'owner-emergency@example.com',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Harness {
  readonly provider: TurnstileCaptchaProvider;
  readonly logger: { warn: jest.Mock };
}

function harness(
  fetchMock: jest.Mock,
  options: TurnstileProviderOptions = {},
  logger: { warn: jest.Mock } = { warn: jest.fn() },
): Harness {
  return {
    provider: new TurnstileCaptchaProvider(
      SECRET,
      options,
      fetchMock as unknown as typeof fetch,
      logger,
    ),
    logger,
  };
}

describe('TurnstileCaptchaProvider request', () => {
  it('posts the secret, token and client ip as form data', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true }));
    const { provider } = harness(fetchMock);

    await expect(provider.verify(TOKEN, IP)).resolves.toBe(true);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(TURNSTILE_VERIFY_URL);
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });

    const body = new URLSearchParams(String(init.body));
    expect(body.get('secret')).toBe(SECRET);
    expect(body.get('response')).toBe(TOKEN);
    expect(body.get('remoteip')).toBe(IP);
    expect([...body.keys()].sort()).toEqual(['remoteip', 'response', 'secret']);
  });

  it('omits remoteip when no client ip is available', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true }));
    const { provider } = harness(fetchMock);

    await provider.verify(TOKEN);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = new URLSearchParams(String(init.body));
    expect(body.has('remoteip')).toBe(false);
    expect([...body.keys()].sort()).toEqual(['response', 'secret']);
  });
});

describe('TurnstileCaptchaProvider decisions', () => {
  it('accepts an explicit success', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(true);
  });

  it('rejects success:false without throwing (call sites raise the generic 400)', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(
        jsonResponse({ success: false, 'error-codes': ['invalid-input-response'] }),
      );
    const { provider } = harness(fetchMock);

    await expect(provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not retry a non-2xx client error', async () => {
    const fetchMock = jest.fn().mockResolvedValue(new Response('bad request', { status: 400 }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('accepts a matching hostname case-insensitively', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ success: true, hostname: 'APP.Example' }));
    await expect(
      harness(fetchMock, { expectedHostname: 'app.example' }).provider.verify(TOKEN),
    ).resolves.toBe(true);
  });

  it('rejects a hostname mismatch', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ success: true, hostname: 'evil.example' }));
    await expect(
      harness(fetchMock, { expectedHostname: 'app.example' }).provider.verify(TOKEN),
    ).resolves.toBe(false);
  });

  it('rejects when a hostname is expected but missing from the response', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true }));
    await expect(
      harness(fetchMock, { expectedHostname: 'app.example' }).provider.verify(TOKEN),
    ).resolves.toBe(false);
  });

  it('skips the hostname check when none is configured', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ success: true, hostname: 'anything.example' }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(true);
  });

  it('accepts a matching action', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ success: true, action: 'otp-start' }));
    await expect(
      harness(fetchMock, { expectedAction: 'otp-start' }).provider.verify(TOKEN),
    ).resolves.toBe(true);
  });

  it('rejects an action mismatch', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true, action: 'login' }));
    await expect(
      harness(fetchMock, { expectedAction: 'otp-start' }).provider.verify(TOKEN),
    ).resolves.toBe(false);
  });
});

describe('TurnstileCaptchaProvider local token checks', () => {
  it.each([
    ['an empty token', ''],
    ['a whitespace-only token', '   '],
    ['an oversized token', 'x'.repeat(TURNSTILE_MAX_TOKEN_LENGTH + 1)],
  ])('rejects %s without any network call', async (_label, token) => {
    const fetchMock = jest.fn();
    await expect(harness(fetchMock).provider.verify(token)).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a non-string token without any network call', async () => {
    const fetchMock = jest.fn();
    await expect(harness(fetchMock).provider.verify(42 as unknown as string)).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts a token of exactly the maximum length', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: true }));
    await expect(
      harness(fetchMock).provider.verify('x'.repeat(TURNSTILE_MAX_TOKEN_LENGTH)),
    ).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('TurnstileCaptchaProvider malformed responses', () => {
  it('rejects invalid JSON', async () => {
    const fetchMock = jest.fn().mockResolvedValue(new Response('not json', { status: 200 }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a payload that does not match the schema', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({ success: 'yes' }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('TurnstileCaptchaProvider retries and outages', () => {
  it('retries once after a 5xx and then accepts', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, 500))
      .mockResolvedValueOnce(jsonResponse({ success: true }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('retries once after a network error and then accepts', async () => {
    const fetchMock = jest
      .fn()
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(jsonResponse({ success: true }));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('fails closed when the 5xx persists after the retry', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({}, 503));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('fails closed when the network error persists after the retry', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new TypeError('fetch failed'));
    await expect(harness(fetchMock).provider.verify(TOKEN)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('aborts a timed-out request and retries once before failing closed', async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = jest.fn().mockImplementation(
        (_url: string, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError')),
            );
          }),
      );
      const { provider } = harness(fetchMock);

      const pending = provider.verify(TOKEN);
      const assertion = expect(pending).resolves.toBe(false);
      await jest.advanceTimersByTimeAsync(5_100);
      await jest.advanceTimersByTimeAsync(5_100);
      await assertion;

      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('TurnstileCaptchaProvider log hygiene', () => {
  it('never logs the secret, token, or the upstream body', async () => {
    const body = `SECRET_BODY ${TOKEN} ${SECRET}`;
    const fetchMock = jest.fn().mockResolvedValue(new Response(body, { status: 500 }));
    const { provider, logger } = harness(fetchMock);

    await expect(provider.verify(TOKEN)).resolves.toBe(false);

    const logs = JSON.stringify(logger.warn.mock.calls);
    expect(logs).not.toContain(SECRET);
    expect(logs).not.toContain(TOKEN);
    expect(logs).not.toContain('SECRET_BODY');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('never logs or rethrows the failure message of a broken transport', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error(`boom ${TOKEN} ${SECRET}`));
    const { provider, logger } = harness(fetchMock);

    await expect(provider.verify(TOKEN)).resolves.toBe(false);

    const logs = JSON.stringify(logger.warn.mock.calls);
    expect(logs).not.toContain(SECRET);
    expect(logs).not.toContain(TOKEN);
    expect(logs).not.toContain('boom');
  });
});

describe('createCaptchaProvider with turnstile', () => {
  it('builds the real verifier when turnstile is selected', () => {
    const env = loadEnv({
      ...DEV_ENV,
      CAPTCHA_PROVIDER: 'turnstile',
      TURNSTILE_SECRET_KEY: SECRET,
    });

    expect(createCaptchaProvider(env)).toBeInstanceOf(TurnstileCaptchaProvider);
  });

  it('refuses to build turnstile without a secret', () => {
    expect(() =>
      createCaptchaProvider({ NODE_ENV: 'development', CAPTCHA_PROVIDER: 'turnstile' }),
    ).toThrow(/TURNSTILE_SECRET_KEY/);
  });

  it('still refuses the fake in production', () => {
    expect(() =>
      createCaptchaProvider({ NODE_ENV: 'production', CAPTCHA_PROVIDER: 'fake' }),
    ).toThrow(/CAPTCHA_PROVIDER=fake is not allowed in NODE_ENV=production/);
  });

  it('keeps the fake as the development default', async () => {
    const env = loadEnv(DEV_ENV);

    expect(env.CAPTCHA_PROVIDER).toBe('fake');
    const provider = createCaptchaProvider(env);
    expect(provider).toBeInstanceOf(FakeCaptchaProvider);
    await expect(provider.verify('fake-captcha-token')).resolves.toBe(true);
  });
});

describe('production environment contract', () => {
  it('boots with turnstile, a secret and an expected hostname', () => {
    const env = loadEnv(PROD_ENV);

    expect(env.CAPTCHA_PROVIDER).toBe('turnstile');
    expect(env.TURNSTILE_EXPECTED_HOSTNAME).toBe('app.example');
    expect(createCaptchaProvider(env)).toBeInstanceOf(TurnstileCaptchaProvider);
  });

  it('refuses to boot without TURNSTILE_SECRET_KEY', () => {
    expect(() => loadEnv({ ...PROD_ENV, TURNSTILE_SECRET_KEY: undefined })).toThrow(
      /TURNSTILE_SECRET_KEY/,
    );
  });

  it('refuses to boot without TURNSTILE_EXPECTED_HOSTNAME', () => {
    expect(() => loadEnv({ ...PROD_ENV, TURNSTILE_EXPECTED_HOSTNAME: undefined })).toThrow(
      /TURNSTILE_EXPECTED_HOSTNAME/,
    );
  });

  it('refuses the fake captcha in production', () => {
    expect(() => loadEnv({ ...PROD_ENV, CAPTCHA_PROVIDER: 'fake' })).toThrow(
      /CAPTCHA_PROVIDER.*turnstile/,
    );
  });

  it('refuses an unknown captcha provider value', () => {
    expect(() => loadEnv({ ...PROD_ENV, CAPTCHA_PROVIDER: 'recaptcha' })).toThrow(
      /CAPTCHA_PROVIDER/,
    );
  });
});
