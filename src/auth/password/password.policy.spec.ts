import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  validatePassword,
  type PasswordIdentityContext,
} from './password.policy';

function reasonOf(password: unknown, identity?: PasswordIdentityContext): string {
  const result = validatePassword(password, identity);
  return result.ok ? 'ok' : result.reason;
}

describe('validatePassword', () => {
  it('accepts a long passphrase, spaces included', () => {
    expect(validatePassword('correct horse battery staple')).toEqual({ ok: true });
    expect(reasonOf('  the quick brown fox jumps over  ')).toBe('ok');
  });

  it('accepts a non-Latin passphrase', () => {
    expect(reasonOf('Пароль-это-длинная-фраза')).toBe('ok');
    expect(reasonOf('كلمة-المرور-الطويلة')).toBe('ok');
  });

  it('does not require digits or symbols', () => {
    expect(reasonOf('correcthorsebatterystaple')).toBe('ok');
  });

  it('accepts exactly the minimum length and rejects one code point fewer', () => {
    expect(PASSWORD_MIN_LENGTH).toBe(12);
    expect(reasonOf('aB3!kL9#mN2@')).toBe('ok');
    expect(reasonOf('aB3!kL9#mN2')).toBe('too_short');
  });

  it('accepts exactly the maximum length and rejects one code point more', () => {
    const block = 'Xk3!mQ9#vL2@pR7$';
    const longest = block.repeat(PASSWORD_MAX_LENGTH / block.length);
    expect(Array.from(longest).length).toBe(PASSWORD_MAX_LENGTH);
    expect(reasonOf(longest)).toBe('ok');
    expect(reasonOf(`${longest}a`)).toBe('too_long');
  });

  it('counts astral characters as one code point each', () => {
    const tenEmoji = '🚀🌟🎉🌍🍀🔥🌊🌙⭐🎯';
    expect(reasonOf(tenEmoji)).toBe('too_short');
    expect(reasonOf(`${tenEmoji}🎸🎨`)).toBe('ok');
  });

  it('rejects anything that is not a string', () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
      expect(reasonOf(value)).toBe('invalid');
    }
  });

  it('rejects control characters and unpaired surrogates', () => {
    expect(reasonOf('correct horse\u0007battery')).toBe('invalid');
    expect(reasonOf('correct horse\u009bbattery')).toBe('invalid');
    expect(reasonOf('correct\nhorse-battery')).toBe('invalid');
    expect(reasonOf('abcdefghijk\uD800')).toBe('invalid');
  });

  it('rejects the denylisted favourites', () => {
    expect(reasonOf('password1234')).toBe('common');
    expect(reasonOf('qwertyuiop123')).toBe('common');
    expect(reasonOf('PassWord1234')).toBe('common');
  });

  it('rejects a password that contains the email local part', () => {
    const identity = { email: 'Alice.Wonderland@example.com' };
    expect(reasonOf('alice.wonderland-2026', identity)).toBe('contains_identity');
    expect(reasonOf('ALICE.WONDERLAND-2026', identity)).toBe('contains_identity');
    expect(reasonOf('xalice.wonderland', identity)).toBe('contains_identity');
  });

  it('rejects a password that contains the username', () => {
    expect(reasonOf('zebra-crossing-9', { username: 'Zebra' })).toBe('contains_identity');
  });

  it('ignores identity terms shorter than four code points', () => {
    expect(reasonOf('the-abc-of-things', { username: 'abc' })).toBe('ok');
    expect(reasonOf('a-b-c-is-the-thing', { username: 'abc' })).toBe('ok');
  });

  it('folds the identity and the password the same way before comparing', () => {
    // Full-width strokes normalise to ASCII, so this is "useruseruser".
    expect(reasonOf('ｕｓｅｒｕｓｅｒｕｓｅｒ', { email: 'user@example.com' })).toBe(
      'contains_identity',
    );
  });

  it('rejects a single repeated character', () => {
    expect(reasonOf('aaaaaaaaaaaa')).toBe('repetitive');
    expect(reasonOf('555555555555')).toBe('repetitive');
  });

  it('rejects ascending and descending runs', () => {
    expect(reasonOf('234567890123')).toBe('repetitive');
    expect(reasonOf('abcdefghijkl')).toBe('repetitive');
    expect(reasonOf('zyxwvutsrqpo')).toBe('repetitive');
  });

  it('rejects an obviously repeated block', () => {
    expect(reasonOf('abcabcabcabc')).toBe('repetitive');
    expect(reasonOf('Kx7!Kx7!Kx7!')).toBe('repetitive');
  });

  it('accepts a password that merely contains a short run', () => {
    expect(reasonOf('Xk9!abc123-Zebra')).toBe('ok');
  });

  it('reports invalid before length and common before repetitive', () => {
    expect(reasonOf('\u0007')).toBe('invalid');
    expect(reasonOf('123456789012')).toBe('common');
  });
});
