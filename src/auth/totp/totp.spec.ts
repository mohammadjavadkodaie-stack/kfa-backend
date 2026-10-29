import { randomBytes } from 'node:crypto';
import {
  base32Decode,
  base32Encode,
  buildOtpauthUri,
  generateTotpSecret,
  hotp,
  totpAt,
  verifyTotp,
} from './totp';

/** The ASCII secret every RFC 4226 / 6238 test vector uses. */
const RFC_SECRET = Buffer.from('12345678901234567890', 'ascii');

describe('base32', () => {
  // RFC 4648 section 10.
  it.each([
    ['', ''],
    ['f', 'MY'],
    ['fo', 'MZXQ'],
    ['foo', 'MZXW6'],
    ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI'],
  ])('encodes "%s" as "%s"', (plain, encoded) => {
    expect(base32Encode(Buffer.from(plain, 'ascii'))).toBe(encoded);
    expect(base32Decode(encoded).toString('ascii')).toBe(plain);
  });

  it('accepts lowercase, spaces and padding', () => {
    expect(base32Decode('mzxw 6ytb oi==').toString('ascii')).toBe('foobar');
  });

  it('round-trips random bytes', () => {
    const data = randomBytes(37);

    expect(base32Decode(base32Encode(data))).toEqual(data);
  });

  it('encodes a generated secret unpadded', () => {
    const secret = generateTotpSecret();

    expect(secret).toHaveLength(20);
    expect(base32Encode(secret)).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(base32Encode(secret))).toEqual(secret);
  });

  it('refuses characters outside the alphabet', () => {
    expect(() => base32Decode('MZXW1')).toThrow(/invalid base32/);
    expect(() => base32Decode('MZXW0')).toThrow(/invalid base32/);
  });
});

describe('hotp', () => {
  // RFC 4226 appendix D, counters 0-9.
  const COUNTERS: ReadonlyArray<readonly [bigint, string]> = [
    [0n, '755224'],
    [1n, '287082'],
    [2n, '359152'],
    [3n, '969429'],
    [4n, '338314'],
    [5n, '254676'],
    [6n, '287922'],
    [7n, '162583'],
    [8n, '399871'],
    [9n, '520489'],
  ];

  it.each(COUNTERS)('matches the RFC 4226 vector for counter %s', (counter, code) => {
    expect(hotp(RFC_SECRET, counter)).toBe(code);
  });
});

describe('totpAt', () => {
  // RFC 6238 appendix B, SHA1 row. The last six digits are what a 6-digit

  describe('verifyTotp', () => {
    const SECRET = Buffer.from('kfa-test-only-totp-secret', 'ascii');
    const STEP_MS = 30_000;
    const NOW = 1_700_000_000_000;
    const CURRENT_STEP = Math.floor(NOW / STEP_MS);

    it('accepts the current step and returns it', () => {
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW), NOW)).toBe(CURRENT_STEP);
    });

    it('accepts one step either side and returns that step', () => {
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW - STEP_MS), NOW)).toBe(CURRENT_STEP - 1);
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW + STEP_MS), NOW)).toBe(CURRENT_STEP + 1);
    });

    it('rejects two steps away', () => {
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW - 2 * STEP_MS), NOW)).toBeNull();
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW + 2 * STEP_MS), NOW)).toBeNull();
    });

    it('widens only when the caller asks for it', () => {
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW + 2 * STEP_MS), NOW, { window: 2 })).toBe(
        CURRENT_STEP + 2,
      );
      expect(verifyTotp(SECRET, totpAt(SECRET, NOW), NOW, { window: 0 })).toBe(CURRENT_STEP);
    });

    it('honours a custom step and digit count', () => {
      const options = { stepSeconds: 60, digits: 8 } as const;

      expect(verifyTotp(SECRET, totpAt(SECRET, NOW, options), NOW, options)).toBe(
        Math.floor(NOW / 1_000 / 60),
      );
    });

    it('rejects a code from another secret', () => {
      const other = Buffer.from('kfa-test-only-other-secret', 'ascii');

      expect(verifyTotp(SECRET, totpAt(other, NOW), NOW)).toBeNull();
    });

    // No spaces, no signs, no other lengths: authenticator apps never send those.
    it.each([
      ['five digits', '12345'],
      ['seven digits', '1234567'],
      ['letters', '12345a'],
      ['spaces', '12 34 56'],
      ['empty', ''],
      ['signed', '+12345'],
      ['non-ascii digits', '\u0661\u0662\u0663\u0664\u0665\u0666'],
    ])('rejects %s', (_label, code) => {
      expect(verifyTotp(SECRET, code, NOW)).toBeNull();
    });
  });

  describe('buildOtpauthUri', () => {
    it('builds a SHA1 / 6 digit / 30 second URI', () => {
      expect(
        buildOtpauthUri({ issuer: 'KFA', label: 'user@example.com', secretBase32: 'MZXW6YTBOI' }),
      ).toBe(
        'otpauth://totp/KFA:user%40example.com' +
          '?secret=MZXW6YTBOI&issuer=KFA&algorithm=SHA1&digits=6&period=30',
      );
    });

    it('encodes an issuer with a space in both places', () => {
      const uri = buildOtpauthUri({
        issuer: 'KFA Auth',
        label: 'staff-42',
        secretBase32: 'MZXW6YTBOI',
      });

      expect(uri).toContain('otpauth://totp/KFA%20Auth:staff-42?');
      expect(uri).toContain('&issuer=KFA%20Auth&');
      expect(uri).not.toContain('KFA Auth');
    });

    it('encodes special characters instead of passing them through', () => {
      const uri = buildOtpauthUri({
        issuer: 'KFA & Co',
        label: 'a/b?c#d',
        secretBase32: 'MZXW6YTBOI',
      });

      expect(uri).toContain('otpauth://totp/KFA%20%26%20Co:');
      expect(uri).toContain('a%2Fb%3Fc%23d');
      expect(uri).not.toContain('?c#d');
    });

    it('keeps the secret inside the secret parameter only', () => {
      const secretBase32 = 'MZXW6YTBOI';
      const uri = buildOtpauthUri({ issuer: 'KFA', label: 'staff-42', secretBase32 });
      const [head, query] = uri.split('?');

      expect(head).not.toContain(secretBase32);
      expect(uri.split(secretBase32)).toHaveLength(2);
      expect(query).toContain(`secret=${secretBase32}&`);
    });
  });

  // authenticator app shows for the same counter.
  const TIMES: ReadonlyArray<readonly [number, string, string]> = [
    [59, '94287082', '287082'],
    [1111111109, '07081804', '081804'],
    [1111111111, '14050471', '050471'],
    [1234567890, '89005924', '005924'],
    [2000000000, '69279037', '279037'],
    [20000000000, '65353130', '353130'],
  ];

  it.each(TIMES)('matches the RFC 6238 vector at %i seconds', (seconds, eightDigits, sixDigits) => {
    expect(totpAt(RFC_SECRET, seconds * 1_000, { digits: 8 })).toBe(eightDigits);
    expect(totpAt(RFC_SECRET, seconds * 1_000)).toBe(sixDigits);
  });
});
