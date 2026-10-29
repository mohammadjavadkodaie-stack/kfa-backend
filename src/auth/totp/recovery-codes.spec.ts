import {
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
  recoveryCodeMatches,
} from './recovery-codes';

const KEY = Buffer.alloc(32, 0x11);
const OTHER_KEY = Buffer.alloc(32, 0x12);
const CODE = 'ABCDE-23456';

describe('generateRecoveryCodes', () => {
  it('returns ten formatted, unique codes', () => {
    const codes = generateRecoveryCodes();

    expect(codes).toHaveLength(10);

    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    }

    expect(new Set(codes).size).toBe(codes.length);
  });

  it('honours a smaller count', () => {
    const codes = generateRecoveryCodes(3);

    expect(codes).toHaveLength(3);
    expect(new Set(codes).size).toBe(3);
  });

  it('refuses a nonsensical count', () => {
    expect(() => generateRecoveryCodes(0)).toThrow(RangeError);
    expect(() => generateRecoveryCodes(101)).toThrow(RangeError);
    expect(() => generateRecoveryCodes(1.5)).toThrow(RangeError);
  });
});

describe('normalizeRecoveryCode', () => {
  it.each(['ABCDE-23456', 'abcde-23456', 'ABCDE23456', 'ABCDE 23456', ' abcde 23456 '])(
    'normalizes %s',
    (input) => {
      expect(normalizeRecoveryCode(input)).toBe('ABCDE23456');
    },
  );

  it.each(['', 'ABCDE-2345', 'ABCDE-234567', 'ABCDE-23450', 'ABCDE_23456', 'ABCDE-2345_6'])(
    'refuses %s',
    (input) => {
      expect(normalizeRecoveryCode(input)).toBeNull();
    },
  );

  it('refuses values that are not strings', () => {
    expect(normalizeRecoveryCode(null)).toBeNull();
    expect(normalizeRecoveryCode(undefined)).toBeNull();
    expect(normalizeRecoveryCode(1234567890)).toBeNull();
  });
});

describe('hashRecoveryCode', () => {
  it('hashes every formatting variant identically', () => {
    const expected = hashRecoveryCode(CODE, KEY);

    expect(hashRecoveryCode('abcde-23456', KEY)).toBe(expected);
    expect(hashRecoveryCode('ABCDE23456', KEY)).toBe(expected);
    expect(hashRecoveryCode(' abcde 23456 ', KEY)).toBe(expected);
  });

  it('returns 64 hex characters without the code inside', () => {
    const hash = hashRecoveryCode(CODE, KEY);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash.toUpperCase()).not.toContain('ABCDE23456');
  });

  it('differs per code and per key', () => {
    expect(hashRecoveryCode(CODE, KEY)).not.toBe(hashRecoveryCode('ABCDE-23457', KEY));
    expect(hashRecoveryCode(CODE, KEY)).not.toBe(hashRecoveryCode(CODE, OTHER_KEY));
  });

  it('refuses a malformed code', () => {
    expect(() => hashRecoveryCode('nope', KEY)).toThrow(/invalid recovery code/);
  });
});

describe('recoveryCodeMatches', () => {
  it('matches the stored hash whatever the formatting', () => {
    const stored = hashRecoveryCode(CODE, KEY);

    expect(recoveryCodeMatches('ABCDE-23456', stored, KEY)).toBe(true);
    expect(recoveryCodeMatches('abcde 23456', stored, KEY)).toBe(true);
  });

  it('refuses another code, key or stored hash', () => {
    const stored = hashRecoveryCode(CODE, KEY);

    expect(recoveryCodeMatches('ABCDE-23457', stored, KEY)).toBe(false);
    expect(recoveryCodeMatches(CODE, stored, OTHER_KEY)).toBe(false);
    expect(recoveryCodeMatches(CODE, hashRecoveryCode('ZZZZZ-ZZZZZ', KEY), KEY)).toBe(false);
  });

  it('never matches malformed input', () => {
    const stored = hashRecoveryCode(CODE, KEY);

    for (const input of ['', 'ABCDE-2345', 'ABCDE-23450', 'not a code', null, undefined, 42]) {
      expect(recoveryCodeMatches(input, stored, KEY)).toBe(false);
    }
  });

  it('never matches a malformed stored hash', () => {
    expect(recoveryCodeMatches(CODE, 'not-a-hash', KEY)).toBe(false);
    expect(recoveryCodeMatches(CODE, '', KEY)).toBe(false);
    expect(recoveryCodeMatches(CODE, 'a'.repeat(63), KEY)).toBe(false);
  });
});
