const TIMEOUT_MS = 10_000;

/** Renew the cached token this long before PayPal expires it. */
const TOKEN_SKEW_MS = 60_000;

type FetchLike = typeof fetch;

interface TokenReply {
  readonly access_token?: unknown;
  readonly expires_in?: unknown;
}

/**
 * The two calls both PayPal adapters make: an OAuth token and a JSON request.
 *
 * The token is cached, because PayPal counts a token request as its own call and
 * a checkout plus a webhook verification would otherwise ask for one each time.
 * A failure is thrown, never swallowed: the caller turns it into a generic 503
 * (checkout) or a refused delivery (webhook), so an outage can never look like a
 * successful payment.
 */
export class PayPalApi {
  private token: { readonly value: string; readonly expiresAt: number } | null = null;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly baseUrl: string,
    private readonly fetchFn: FetchLike = fetch,
  ) {}

  async json<T>(path: string, request: { method: string; body?: unknown }): Promise<T> {
    const token = await this.accessToken();
    const response = await this.send(`${this.baseUrl}${path}`, {
      method: request.method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      ...(request.body === undefined ? {} : { body: JSON.stringify(request.body) }),
    });

    if (!response.ok) throw new Error(`paypal request failed (${response.status})`);

    return (await response.json()) as T;
  }

  private async accessToken(): Promise<string> {
    const now = Date.now();

    if (this.token !== null && this.token.expiresAt > now) return this.token.value;

    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`, 'utf8').toString('base64');
    const response = await this.send(`${this.baseUrl}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });

    if (!response.ok) throw new Error(`paypal token failed (${response.status})`);

    const reply = (await response.json()) as TokenReply;

    if (typeof reply.access_token !== 'string' || reply.access_token.length === 0) {
      throw new Error('paypal token malformed');
    }

    const lifetimeSeconds = typeof reply.expires_in === 'number' ? reply.expires_in : 300;
    const lifetimeMs = Math.max(0, lifetimeSeconds * 1_000 - TOKEN_SKEW_MS);

    this.token = { value: reply.access_token, expiresAt: now + lifetimeMs };

    return this.token.value;
  }

  /** One request, bounded in time: a hung provider must not hold a worker. */
  private async send(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      return await this.fetchFn(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }
}
