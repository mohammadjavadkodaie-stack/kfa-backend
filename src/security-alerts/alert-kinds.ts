/**
 * Closed set of alert kinds. Adding a kind means editing this list: there is no
 * `string` escape hatch, so a typo is a compile error instead of a silent no-op.
 */
export const SECURITY_ALERT_KINDS = [
  'LOGIN_NEW_COUNTRY',
  'EMAIL_CODE_SURGE',
  'DOCUMENT_VIEW_SURGE',
] as const;

export type SecurityAlertKind = (typeof SECURITY_ALERT_KINDS)[number];
