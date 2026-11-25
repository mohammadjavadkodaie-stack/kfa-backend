import type { SecurityAlertKind } from './alert-kinds';

/**
 * Ids and counters only: no email, phone, IP, token or file name. An alert that
 * cannot carry personal data cannot leak it, whatever transport is plugged in.
 */
export interface SecurityAlert {
  readonly kind: SecurityAlertKind;
  readonly at: Date;
  /** Internal user id (a UUID); never an email address or phone number. */
  readonly subjectId?: string;
  /** ISO 3166-1 alpha-2 code, upper case. */
  readonly country?: string;
  readonly count?: number;
  readonly windowSeconds?: number;
  /** Internal delivery-only value; sinks must never log or audit it raw. */
  readonly ip?: string;
}

/**
 * Alert delivery is best effort: an implementation must not throw into the flow
 * that produced the event (a login or a document read must still succeed).
 */
export interface AlertSink {
  emit(alert: SecurityAlert): Promise<void>;
}

export const ALERT_SINK = Symbol('ALERT_SINK');
