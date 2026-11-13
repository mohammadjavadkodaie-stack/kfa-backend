import { z } from 'zod';
import type { CaptchaProvider } from './captcha.provider';

export const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const TURNSTILE_TIMEOUT_MS = 5_000;
export const TURNSTILE_MAX_TOKEN_LENGTH = 2048;

type FetchLike = typeof fetch;

/** Only a short reason class is ever logged: never the token, secret or response. */
export type TurnstileLogLike = {
  warn: (data: object, message: string) => void;
};

const NOOP_LOGGER: TurnstileLogLike = { warn: () => undefined };

/** The subset of Cloudflare's siteverify payload the verifier trusts. */
const turnstileResponseSchema = z.object({
  success: z.boolean(),
  hostname: z.string().optional(),
  action: z.string().optional(),
  'error-codes': z.array(z.string()).optional(),
});

type TurnstileResponse = z.infer<typeof turnstileResponseSchema>;

export interface TurnstileProviderOptions {
  /** When set, the widget must have solved the challenge for exactly this host. */
  readonly expectedHostname?: string;
  /** When set, the widget action (if any) must match exactly. */
  readonly expectedAction?: string;
}

type AttemptOutcome =
  | { readonly kind: 'response'; readonly data: TurnstileResponse }
  | { readonly kind: 'rejected'; readonly reason: string }
  | { readonly kind: 'retryable'; readonly reason: '5xx' | 'timeout' | 'network' };

/**
 * Cloudflare Turnstile verifier (siteverify), fail-closed.
 *
 * Frontend contract: render the Turnstile widget and put its
 * `cf-turnstile-response` value in the existing `captchaToken` request field
 * (OTP start, email-code start, password reset start). No API shape changes are
 * needed.
 *
 * Any outcome that is not an explicit `success: true` for the configured
 * hostname/action is rejected, and a provider outage after the single retry is
 * also a rejection: a captcha that cannot be checked never becomes a bypass.
 * The call sites keep throwing their generic `BadRequestException`, so callers
 * cannot tell which check failed. Tokens, the secret and Cloudflare's raw
 * response are never logged or included in an error.
 */
export class TurnstileCaptchaProvider implements CaptchaProvider {
  private readonly expectedHostname: string | undefined;
  private readonly expectedAction: string | undefined;

  constructor(
    private readonly secret: string,
    options: TurnstileProviderOptions = {},
    private readonly fetchFn: FetchLike = fetch,
    private readonly logger: TurnstileLogLike = NOOP_LOGGER,
  ) {
    this.expectedHostname = options.expectedHostname;
    this.expectedAction = options.expectedAction;
  }

  async verify(token: string, remoteIp?: string): Promise<boolean> {
    if (!hasValidShape(token)) {
      this.logger.warn({ reason: 'invalid_token' }, 'turnstile verification rejected');
      return false;
    }

    const body = new URLSearchParams({ secret: this.secret, response: token });
    if (typeof remoteIp === 'string' && remoteIp.length > 0) {
      body.set('remoteip', remoteIp);
    }

    let lastRetryReason: '5xx' | 'timeout' | 'network' = 'network';
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const outcome = await this.attempt(body);
      if (outcome.kind === 'retryable') {
        lastRetryReason = outcome.reason;
        if (attempt === 0) await delay(50);
        continue;
      }
      if (outcome.kind === 'rejected') {
        this.logger.warn({ reason: outcome.reason }, 'turnstile verification rejected');
        return false;
      }
      return this.decide(outcome.data);
    }

    // Outage after the retry: fail closed, never accept.
    this.logger.warn({ reason: `outage_${lastRetryReason}` }, 'turnstile verification unavailable');
    return false;
  }

  private decide(data: TurnstileResponse): boolean {
    if (!data.success) {
      this.logger.warn({ reason: 'upstream_rejected' }, 'turnstile verification rejected');
      return false;
    }

    if (
      this.expectedHostname !== undefined &&
      (typeof data.hostname !== 'string' ||
        data.hostname.toLowerCase() !== this.expectedHostname.toLowerCase())
    ) {
      this.logger.warn({ reason: 'hostname_mismatch' }, 'turnstile verification rejected');
      return false;
    }

    if (this.expectedAction !== undefined && data.action !== this.expectedAction) {
      this.logger.warn({ reason: 'action_mismatch' }, 'turnstile verification rejected');
      return false;
    }

    return true;
  }

  private async attempt(body: URLSearchParams): Promise<AttemptOutcome> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TURNSTILE_TIMEOUT_MS);

    try {
      const response = await this.fetchFn(TURNSTILE_VERIFY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        signal: controller.signal,
      });

      // The body of an error response is never read: it may echo the token.
      if (response.status >= 500) return { kind: 'retryable', reason: '5xx' };
      if (response.status < 200 || response.status >= 300) {
        return { kind: 'rejected', reason: `http_${response.status}` };
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        return { kind: 'rejected', reason: 'invalid_json' };
      }

      const parsed = turnstileResponseSchema.safeParse(payload);
      return parsed.success
        ? { kind: 'response', data: parsed.data }
        : { kind: 'rejected', reason: 'invalid_schema' };
    } catch (error) {
      return { kind: 'retryable', reason: isAbortError(error) ? 'timeout' : 'network' };
    } finally {
      clearTimeout(timeout);
    }
  }
}

function hasValidShape(token: unknown): token is string {
  return (
    typeof token === 'string' &&
    token.trim().length > 0 &&
    token.length <= TURNSTILE_MAX_TOKEN_LENGTH
  );
}

function isAbortError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    (error as { name?: unknown }).name === 'AbortError'
  );
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
