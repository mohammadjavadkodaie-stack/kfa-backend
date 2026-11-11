/**
 * Stopgap denylist of disposable/throwaway email providers.
 *
 * This list is deliberately small and embedded: the email identity flow is only
 * starting to replace phone + SMS OTP, and blocking the most common throwaway
 * domains is better than nothing. It is NOT a security boundary - a determined
 * user can always register a new domain - so replace it with a maintained feed
 * (or a paid reputation service) before email registration opens to the public.
 * Keep the entries lowercase and punycode-encoded, exactly like `users.email`.
 */
const DISPOSABLE_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
  '10minutemail.com',
  'dispostable.com',
  'dropmail.me',
  'emailondeck.com',
  'fakeinbox.com',
  'getnada.com',
  'grr.la',
  'guerrillamail.biz',
  'guerrillamail.com',
  'guerrillamail.de',
  'guerrillamail.info',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamailblock.com',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'mintemail.com',
  'mohmal.com',
  'mytemp.email',
  'sharklasers.com',
  'spam4.me',
  'spamgourmet.com',
  'temp-mail.io',
  'temp-mail.org',
  'tempmail.com',
  'tempmailo.com',
  'throwawaymail.com',
  'trashmail.com',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
]);

/**
 * True when the (already normalised) address belongs to a known throwaway
 * provider. Parent domains are matched too, so `anything@inbox.mailinator.com`
 * is caught as well. Missing or malformed input is simply "not disposable".
 */
export function isDisposableEmailDomain(normalized: string): boolean {
  if (typeof normalized !== 'string') return false;

  const at = normalized.lastIndexOf('@');

  if (at < 0) return false;

  const domain = normalized.slice(at + 1).toLowerCase();

  if (domain.length === 0) return false;

  const labels = domain.split('.');

  for (let index = 0; index < labels.length; index += 1) {
    if (DISPOSABLE_EMAIL_DOMAINS.has(labels.slice(index).join('.'))) return true;
  }

  return false;
}
