import { domainToASCII } from 'node:url';

export { isDisposableEmailDomain } from './disposable-domains';

/** Longest address accepted by the `users_email_length_check` constraint. */
const MAX_EMAIL_LENGTH = 254;

/**
 * The exact rule of the `users_email_format_check` CHECK constraint:
 *   ^[a-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}[.])+[a-z]{2,63}$
 *
 * Keeping the two in lockstep means an address accepted here can never be
 * rejected by Postgres (or the other way round) once the email identity flow
 * starts writing rows.
 */
const EMAIL_FORMAT = /^[a-z0-9._%+-]{1,64}@([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/u;

/**
 * Local part as typed: ASCII only. Checking this before lowercasing blocks
 * Unicode case-folding tricks (the Kelvin sign `K` lowercases to `k`), which
 * would otherwise smuggle a non-ASCII character into the stored address.
 */
const LOCAL_FORMAT = /^[A-Za-z0-9._%+-]{1,64}$/u;

/** No control character and no whitespace may live inside an address. */
const CONTROL_OR_WHITESPACE = /[\s\u0000-\u001f\u007f-\u009f]/u;

const INVALID_EMAIL = '[INVALID_EMAIL]';

/**
 * Normalises an email address to the form stored in `users.email`, or returns
 * `null` when it fails any rule. It never throws: callers can treat `null` as
 * "the user typed something unusable" without a try/catch.
 *
 * Steps: trim, refuse inner whitespace/control characters, require exactly one
 * `@`, lowercase the local part (ASCII only), convert the domain to punycode
 * (`node:url` `domainToASCII`) and lowercase it, then enforce the database
 * format rule and the 254-character cap.
 */
export function normalizeEmail(input: string): string | null {
  if (typeof input !== 'string') return null;

  try {
    const trimmed = input.trim();

    if (trimmed.length === 0) return null;
    if (trimmed.length > MAX_EMAIL_LENGTH) return null;
    if (CONTROL_OR_WHITESPACE.test(trimmed)) return null;

    const parts = trimmed.split('@');

    if (parts.length !== 2) return null;

    const rawLocal = parts[0];
    const rawDomain = parts[1];

    // `noUncheckedIndexedAccess` widens indexed reads; the length check above
    // already guarantees both parts exist.
    if (rawLocal === undefined || rawDomain === undefined) return null;
    if (!LOCAL_FORMAT.test(rawLocal)) return null;

    const domain = domainToASCII(rawDomain.toLowerCase());

    if (domain.length === 0) return null;

    const normalized = `${rawLocal.toLowerCase()}@${domain.toLowerCase()}`;

    if (normalized.length > MAX_EMAIL_LENGTH) return null;

    return EMAIL_FORMAT.test(normalized) ? normalized : null;
  } catch {
    // `domainToASCII` should not throw, but a never-throwing contract is worth
    // more here than a diagnostic nobody can act on.
    return null;
  }
}

/**
 * Masks a normalised address for logs and audit metadata: `i***@example.com`.
 * The domain is kept on purpose (support needs it), the local part is not.
 * A value that is not already normalised yields a constant placeholder instead
 * of leaking an unvalidated string.
 */
export function maskEmail(normalized: string): string {
  if (typeof normalized !== 'string') return INVALID_EMAIL;
  if (normalized.length > MAX_EMAIL_LENGTH) return INVALID_EMAIL;
  if (!EMAIL_FORMAT.test(normalized)) return INVALID_EMAIL;

  return `${normalized.charAt(0)}***@${normalized.slice(normalized.indexOf('@') + 1)}`;
}
