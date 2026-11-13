import { ResendEmailProvider } from './resend-email.provider';

const ADDRESS = 'person@example.com';
const KEY = 're_test_secret_key';
const response = (status: number): Response => new Response('{}', { status });

function fetchMockFactory(): jest.MockedFunction<typeof fetch> {
  return jest.fn() as unknown as jest.MockedFunction<typeof fetch>;
}

function provider(
  fetchFn: typeof fetch = fetch,
  logger = { info: jest.fn(), warn: jest.fn() },
): ResendEmailProvider {
  return new ResendEmailProvider(KEY, 'KFA <no-reply@example.com>', 600, fetchFn, logger);
}

describe('ResendEmailProvider', () => {
  beforeEach(() => jest.restoreAllMocks());

  it.each([
    'register',
    'login_device',
    'password_reset',
    'email_change_new',
    'email_change_old',
  ] as const)('sends the %s code with the Resend request shape', async (purpose) => {
    const fetchMock = fetchMockFactory().mockResolvedValue(response(200));
    await provider(fetchMock).sendCode({ to: ADDRESS, purpose, code: '123456' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe('https://api.resend.com/emails');
    expect(init?.method).toBe('POST');
    expect(init?.headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toEqual(
      expect.any(String),
    );
    expect(JSON.parse(String(init?.body))).toMatchObject({
      from: 'KFA <no-reply@example.com>',
      to: [ADDRESS],
      subject: expect.any(String),
      text: expect.stringContaining('123456'),
    });
  });

  it('sends notice templates without a secret', async () => {
    const fetchMock = fetchMockFactory().mockResolvedValue(response(200));
    await provider(fetchMock).sendNotice({ to: ADDRESS, kind: 'password_changed' });
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(body.subject).toContain('password');
    expect(body.text).not.toContain(KEY);
    expect(body.text).not.toContain(ADDRESS);
  });

  it('uses different idempotency keys for separate sends', async () => {
    const fetchMock = fetchMockFactory().mockResolvedValue(response(200));
    await provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '111111' });
    await provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '222222' });
    const first = (fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ];
    const second = (fetchMock.mock.calls[1]?.[1]?.headers as Record<string, string>)[
      'Idempotency-Key'
    ];
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first).not.toBe(second);
  });

  it('renders four locales with distinct subjects and the code', async () => {
    const subjects: string[] = [];
    for (const locale of ['en', 'fa', 'tr', 'ar'] as const) {
      const fetchMock = fetchMockFactory().mockResolvedValue(response(200));
      await provider(fetchMock).sendCode({
        to: ADDRESS,
        purpose: 'register',
        code: '654321',
        locale,
      });
      const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
      subjects.push(body.subject);
      expect(body.subject).toBeTruthy();
      expect(body.text).toContain('654321');
    }
    expect(new Set(subjects).size).toBe(4);
  });

  it('derives the validity window from the configured TTL, in each locale', async () => {
    const fetchMock = fetchMockFactory().mockResolvedValue(response(200));
    const fifteenMinutes = new ResendEmailProvider(
      KEY,
      'KFA <no-reply@example.com>',
      900,
      fetchMock,
      {
        info: jest.fn(),
        warn: jest.fn(),
      },
    );
    await fifteenMinutes.sendCode({
      to: ADDRESS,
      purpose: 'register',
      code: '123456',
      locale: 'en',
    });
    await fifteenMinutes.sendCode({
      to: ADDRESS,
      purpose: 'register',
      code: '123456',
      locale: 'fa',
    });
    const [english, persian] = [0, 1].map((index) =>
      JSON.parse(String(fetchMock.mock.calls[index]?.[1]?.body)),
    );
    expect(english.text).toContain('15 minutes');
    expect(persian.text).toContain('۱۵ دقیقه');
  });

  it('resolves on success', async () => {
    await expect(
      provider(fetchMockFactory().mockResolvedValue(response(202))).sendNotice({
        to: ADDRESS,
        kind: 'email_changed',
      }),
    ).resolves.toBeUndefined();
  });

  it.each([500, 502, 429])('retries one %s response and then succeeds', async (status) => {
    const fetchMock = fetchMockFactory()
      .mockResolvedValueOnce(response(status))
      .mockResolvedValueOnce(response(200));
    await expect(
      provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' }),
    ).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('retries a network failure once', async () => {
    const fetchMock = fetchMockFactory()
      .mockRejectedValueOnce(new Error('socket secret'))
      .mockResolvedValueOnce(response(200));
    await expect(
      provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' }),
    ).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([400, 401, 403, 422])('does not retry a %s response', async (status) => {
    const fetchMock = fetchMockFactory().mockResolvedValue(response(status));
    await expect(
      provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' }),
    ).rejects.toThrow(`(${status})`);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('throws a sanitized error after retry exhaustion', async () => {
    const body = 'api_key=SECRET_BODY recipient=person@example.com code=123456';
    const fetchMock = fetchMockFactory().mockResolvedValue(new Response(body, { status: 500 }));
    await expect(
      provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' }),
    ).rejects.toThrow(/resend email delivery failed \(5xx\)/u);
    try {
      await provider(fetchMock).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' });
    } catch (error) {
      const message = String(error);
      expect(message).not.toContain(KEY);
      expect(message).not.toContain(ADDRESS);
      expect(message).not.toContain('123456');
      expect(message).not.toContain('SECRET_BODY');
    }
  });

  it('aborts a timed out request and retries once', async () => {
    jest.useFakeTimers();
    try {
      const fetchMock = fetchMockFactory().mockImplementation(
        (_url, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError')),
            );
          }),
      );
      const pending = provider(fetchMock).sendCode({
        to: ADDRESS,
        purpose: 'register',
        code: '123456',
      });
      const assertion = expect(pending).rejects.toThrow('(timeout)');
      await jest.advanceTimersByTimeAsync(8_100);
      await jest.advanceTimersByTimeAsync(8_100);
      await assertion;
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it('logs no code, key, or full address', async () => {
    const logger = { info: jest.fn(), warn: jest.fn() };
    const fetchMock = fetchMockFactory().mockResolvedValue(response(500));
    await expect(
      provider(fetchMock, logger).sendCode({ to: ADDRESS, purpose: 'register', code: '123456' }),
    ).rejects.toThrow();
    const logs = JSON.stringify(logger);
    expect(logs).not.toContain(KEY);
    expect(logs).not.toContain(ADDRESS);
    expect(logs).not.toContain('123456');
  });
});
