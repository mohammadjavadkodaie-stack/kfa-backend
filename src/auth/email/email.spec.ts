import { maskEmail, normalizeEmail } from './email';
import { isDisposableEmailDomain } from './disposable-domains';

describe('normalizeEmail', () => {
  it('normalises an ordinary address and trims surrounding whitespace', () => {
    expect(normalizeEmail('user@example.com')).toBe('user@example.com');
    expect(normalizeEmail('  user@example.com  ')).toBe('user@example.com');
  });

  it('keeps plus addressing and dots in the local part', () => {
    expect(normalizeEmail('first.last+tag@example.com')).toBe('first.last+tag@example.com');
  });

  it('lowercases the local part and the domain', () => {
    expect(normalizeEmail('User.Name+Tag@Example.COM')).toBe('user.name+tag@example.com');
  });

  it('converts a Unicode domain to punycode', () => {
    expect(normalizeEmail('user@münchen.de')).toBe('user@xn--mnchen-3ya.de');
    expect(normalizeEmail('USER@MÜNCHEN.DE')).toBe('user@xn--mnchen-3ya.de');
  });

  it('rejects a non-ASCII local part', () => {
    expect(normalizeEmail('üser@example.com')).toBeNull();
    // The Kelvin sign lowercases to "k", so it must be refused before folding.
    expect(normalizeEmail(`${String.fromCodePoint(0x212a)}@example.com`)).toBeNull();
    expect(normalizeEmail('ÜSER@example.com')).toBeNull();
  });

  it('rejects internal spaces and CRLF injection', () => {
    expect(normalizeEmail('us er@example.com')).toBeNull();
    expect(normalizeEmail('user@example.com\r\nBcc: victim@example.com')).toBeNull();
    expect(normalizeEmail('user@exa\tmple.com')).toBeNull();
    expect(normalizeEmail('user@example.com\rBcc: victim@example.com')).toBeNull();
  });

  it('rejects anything without exactly one @', () => {
    expect(normalizeEmail('userexample.com')).toBeNull();
    expect(normalizeEmail('user@@example.com')).toBeNull();
    expect(normalizeEmail('user@mail@example.com')).toBeNull();
  });

  it('accepts a 64-character local part but not a 65-character one', () => {
    const local = 'a'.repeat(64);

    expect(normalizeEmail(`${local}@example.com`)).toBe(`${local}@example.com`);
    expect(normalizeEmail(`${'a'.repeat(65)}@example.com`)).toBeNull();
  });

  it('rejects an address longer than 254 characters', () => {
    const domain = `${['b', 'c', 'd', 'e'].map((label) => label.repeat(63)).join('.')}.com`;
    const address = `a@${domain}`;

    expect(address.length).toBeGreaterThan(254);
    expect(normalizeEmail(address)).toBeNull();
  });

  it('rejects a malformed domain', () => {
    expect(normalizeEmail('user@example')).toBeNull();
    expect(normalizeEmail('user@.com')).toBeNull();
    expect(normalizeEmail('user@example.c')).toBeNull();
    expect(normalizeEmail('user@example.123')).toBeNull();
    expect(normalizeEmail('user@exa_mple.com')).toBeNull();
    expect(normalizeEmail('user@example..com')).toBeNull();
  });

  it('rejects empty and non-string input without throwing', () => {
    expect(normalizeEmail('')).toBeNull();
    expect(normalizeEmail('   ')).toBeNull();
    expect(normalizeEmail(undefined as unknown as string)).toBeNull();
    expect(normalizeEmail(42 as unknown as string)).toBeNull();
  });
});

describe('isDisposableEmailDomain', () => {
  it('detects well-known throwaway domains', () => {
    expect(isDisposableEmailDomain('user@mailinator.com')).toBe(true);
    expect(isDisposableEmailDomain('user@yopmail.com')).toBe(true);
    expect(isDisposableEmailDomain('user@YOPMAIL.FR')).toBe(true);
  });

  it('detects throwaway subdomains through the parent domain', () => {
    expect(isDisposableEmailDomain('user@inbox.mailinator.com')).toBe(true);
  });

  it('does not flag ordinary domains', () => {
    expect(isDisposableEmailDomain('user@example.com')).toBe(false);
    expect(isDisposableEmailDomain('user@gmail.com')).toBe(false);
    expect(isDisposableEmailDomain('user@notmailinator.com')).toBe(false);
  });

  it('returns false for input without a usable domain', () => {
    expect(isDisposableEmailDomain('user')).toBe(false);
    expect(isDisposableEmailDomain('user@')).toBe(false);
    expect(isDisposableEmailDomain('')).toBe(false);
  });
});

describe('maskEmail', () => {
  it('keeps the first character and the domain only', () => {
    expect(maskEmail('ivan@example.com')).toBe('i***@example.com');
    expect(maskEmail('a@b.co')).toBe('a***@b.co');
  });

  it('masks a long local part down to one character', () => {
    const masked = maskEmail('first.last+tag@example.com');

    expect(masked).toBe('f***@example.com');
    expect(masked).not.toContain('last');
    expect(masked).not.toContain('tag');
  });

  it('refuses a value that is not normalised', () => {
    expect(maskEmail('Ivan@example.com')).toBe('[INVALID_EMAIL]');
    expect(maskEmail('not-an-address')).toBe('[INVALID_EMAIL]');
    expect(maskEmail(undefined as unknown as string)).toBe('[INVALID_EMAIL]');
  });
});
