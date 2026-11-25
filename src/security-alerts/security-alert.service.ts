import { Inject, Injectable, Optional } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { ALERT_SINK } from './alert-sink';
import type { AlertSink, SecurityAlert } from './alert-sink';
import { COUNTER_STORE } from './counter-store';
import type { CounterStore } from './counter-store';
import { KNOWN_COUNTRY_STORE } from './known-country-store';
import type { KnownCountryStore } from './known-country-store';

/** Overrides for a deployment that needs other limits; not fed from env yet. */
export const SECURITY_ALERT_OPTIONS = Symbol('SECURITY_ALERT_OPTIONS');

export interface ThresholdWindow {
  readonly threshold: number;
  readonly windowSeconds: number;
}

export interface SecurityAlertOptions {
  /** Global email-code requests: default 50 per 10 minutes. */
  readonly emailCode?: ThresholdWindow;
  /** Document views per actor: default 20 per 10 minutes. */
  readonly documentView?: ThresholdWindow;
  /** Repeat suppression for a new-country login: default 1 hour. */
  readonly loginCountryWindowSeconds?: number;
}

const DEFAULT_EMAIL_CODE: ThresholdWindow = { threshold: 50, windowSeconds: 600 };
const DEFAULT_DOCUMENT_VIEW: ThresholdWindow = { threshold: 20, windowSeconds: 600 };
const DEFAULT_LOGIN_COUNTRY_WINDOW_SECONDS = 3600;

const COUNTRY_PATTERN = /^[A-Z]{2}$/;

/**
 * Pure-logic detectors. They never see a request, so they cannot leak an email,
 * a phone number or a client IP: only ids, a country code and counters.
 */
@Injectable()
export class SecurityAlertService {
  private readonly emailCodeLimits: ThresholdWindow;
  private readonly documentViewLimits: ThresholdWindow;
  private readonly loginCountryWindowSeconds: number;

  constructor(
    @Inject(COUNTER_STORE) private readonly counters: CounterStore,
    @Inject(ALERT_SINK) private readonly sink: AlertSink,
    @Inject(KNOWN_COUNTRY_STORE) private readonly knownCountries: KnownCountryStore,
    @Optional() @Inject(SECURITY_ALERT_OPTIONS) options: SecurityAlertOptions = {},
    @Optional() private readonly logger?: PinoLogger,
  ) {
    this.emailCodeLimits = normalizeThreshold(options.emailCode, DEFAULT_EMAIL_CODE);
    this.documentViewLimits = normalizeThreshold(options.documentView, DEFAULT_DOCUMENT_VIEW);
    this.loginCountryWindowSeconds = positiveInt(
      options.loginCountryWindowSeconds,
      DEFAULT_LOGIN_COUNTRY_WINDOW_SECONDS,
    );
  }

  /**
   * Login from a country the user has never used. The per user+country counter
   * also throttles repeats, so a burst of logins yields one alert per window.
   */
  async loginCountry(userId: string, country: string): Promise<SecurityAlert | null> {
    try {
      if (!userId) return null;

      const code = normalizeCountry(country);
      if (!code || code === 'XX') return null;

      const result = await this.knownCountries.recordAndCheck(userId, code);
      if (!result.isNew || !result.hadAny) return null;

      const key = `login-country:${userId}:${code}`;
      const count = await this.counters.incr(key, this.loginCountryWindowSeconds);
      if (count !== 1) return null;

      return await this.emit({
        kind: 'LOGIN_NEW_COUNTRY',
        at: new Date(),
        subjectId: userId,
        country: code,
      });
    } catch {
      this.logger?.debug({ kind: 'LOGIN_NEW_COUNTRY' }, 'security_alert_failed');
      return null;
    }
  }

  /** Global email-code traffic (an abuse signal, not tied to one account). */
  async emailCodeRequest(): Promise<SecurityAlert | null> {
    try {
      const count = await this.counters.incr(
        'email-code:global',
        this.emailCodeLimits.windowSeconds,
      );
      if (count !== this.emailCodeLimits.threshold) return null;

      return await this.emit({
        kind: 'EMAIL_CODE_SURGE',
        at: new Date(),
        count,
        windowSeconds: this.emailCodeLimits.windowSeconds,
      });
    } catch {
      this.logger?.debug({ kind: 'EMAIL_CODE_SURGE' }, 'security_alert_failed');
      return null;
    }
  }

  /** Repeated failed sign-ins from one source address. */
  async failedLoginIp(ip: string): Promise<SecurityAlert | null> {
    try {
      if (typeof ip !== 'string' || ip.trim().length === 0) return null;

      const normalizedIp = ip.trim();
      const count = await this.counters.incr(`failed-login-ip:${normalizedIp}`, 900);
      if (count !== 6) return null;

      return await this.emit({
        kind: 'FAILED_LOGIN_IP_SURGE',
        at: new Date(),
        count,
        windowSeconds: 900,
        ip: normalizedIp,
      });
    } catch {
      this.logger?.debug({ kind: 'FAILED_LOGIN_IP_SURGE' }, 'security_alert_failed');
      return null;
    }
  }

  /** Document reads per actor: a surge hints at scraping or a stolen session. */
  async documentView(actorId: string): Promise<SecurityAlert | null> {
    try {
      if (!actorId) return null;

      const key = `document-view:${actorId}`;
      const count = await this.counters.incr(key, this.documentViewLimits.windowSeconds);
      if (count !== this.documentViewLimits.threshold) return null;

      return await this.emit({
        kind: 'DOCUMENT_VIEW_SURGE',
        at: new Date(),
        subjectId: actorId,
        count,
        windowSeconds: this.documentViewLimits.windowSeconds,
      });
    } catch {
      this.logger?.debug({ kind: 'DOCUMENT_VIEW_SURGE' }, 'security_alert_failed');
      return null;
    }
  }

  private async emit(alert: SecurityAlert): Promise<SecurityAlert> {
    await this.sink.emit(alert);
    return alert;
  }
}

/** Trims and upper-cases, then rejects anything that is not two ASCII letters. */
function normalizeCountry(value: unknown): string | null {
  if (typeof value !== 'string') return null;

  const code = value.trim().toUpperCase();
  return COUNTRY_PATTERN.test(code) ? code : null;
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : fallback;
}

function normalizeThreshold(
  value: ThresholdWindow | undefined,
  fallback: ThresholdWindow,
): ThresholdWindow {
  return {
    threshold: positiveInt(value?.threshold, fallback.threshold),
    windowSeconds: positiveInt(value?.windowSeconds, fallback.windowSeconds),
  };
}
