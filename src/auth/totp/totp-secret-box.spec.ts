import { base32Encode } from './totp';
import { decryptTotpSecret, encryptTotpSecret } from './totp-secret-box';

const KEY = Buffer.alloc(32, 0x2a);
const OTHER_KEY = Buffer.alloc(32, 0x2b);
const USER_ID = 'user_01JTEST';
const OTHER_USER_ID = 'user_01JOTHER';
const SECRET = Buffer.from('12345678901234567890', 'ascii');

function messageOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    return (error as Error).message;
  }

  throw new Error('expected the call to fail');
}

/** Replaces the first character of one base64url part, so the bytes really change. */
function tamper(stored: string, part: number): string {
  const parts = stored.split('.');
  const target = parts[part] as string;
  const first = target.charAt(0) === 'A' ? 'B' : 'A';

  parts[part] = `${first}${target.slice(1)}`;

  return parts.join('.');
}

describe('totp secret box', () => {
  it('round-trips a secret', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(stored.startsWith('v1.')).toBe(true);
    expect(stored.split('.')).toHaveLength(4);
    expect(decryptTotpSecret(stored, KEY, USER_ID)).toEqual(SECRET);
  });

  it('uses a fresh IV per call', () => {
    const first = encryptTotpSecret(SECRET, KEY, USER_ID);
    const second = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(first).not.toBe(second);
    expect(decryptTotpSecret(second, KEY, USER_ID)).toEqual(SECRET);
  });

  it('refuses another user id', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(() => decryptTotpSecret(stored, KEY, OTHER_USER_ID)).toThrow('totp secret unreadable');
  });

  it.each([
    ['iv', 1],
    ['ciphertext', 2],
    ['tag', 3],
  ])('refuses a tampered %s', (_label, part) => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(() => decryptTotpSecret(tamper(stored, part), KEY, USER_ID)).toThrow(
      'totp secret unreadable',
    );
  });

  it('refuses an unknown version or a broken format', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);
    const [version, ...rest] = stored.split('.');
    const nextVersion = version === 'v1' ? 'v2' : 'v1';

    expect(() => decryptTotpSecret([nextVersion, ...rest].join('.'), KEY, USER_ID)).toThrow(
      'totp secret unreadable',
    );

    for (const broken of ['', 'not-a-box', 'v1.abc', 'v1..frag..tag']) {
      expect(() => decryptTotpSecret(broken, KEY, USER_ID)).toThrow('totp secret unreadable');
    }
  });

  it('refuses the wrong key', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(() => decryptTotpSecret(stored, OTHER_KEY, USER_ID)).toThrow('totp secret unreadable');
  });

  it('rejects a key that is not 32 bytes', () => {
    expect(() => encryptTotpSecret(SECRET, Buffer.alloc(31, 1), USER_ID)).toThrow(
      'totp secret unreadable',
    );
    expect(() => encryptTotpSecret(SECRET, Buffer.alloc(16, 1), USER_ID)).toThrow(
      'totp secret unreadable',
    );

    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);

    expect(() => decryptTotpSecret(stored, Buffer.alloc(31, 1), USER_ID)).toThrow(
      'totp secret unreadable',
    );
  });

  it('never carries the plaintext secret', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);
    const parts = stored.split('.');

    expect(stored).not.toContain(SECRET.toString('utf8'));
    expect(stored).not.toContain(SECRET.toString('hex'));
    expect(stored.toUpperCase()).not.toContain(base32Encode(SECRET));
    expect(parts[2]).not.toBe('');
  });

  it('reports every failure with the same message', () => {
    const stored = encryptTotpSecret(SECRET, KEY, USER_ID);
    const messages = [
      messageOf(() => decryptTotpSecret(stored, OTHER_KEY, USER_ID)),
      messageOf(() => decryptTotpSecret(stored, KEY, OTHER_USER_ID)),
      messageOf(() => decryptTotpSecret(tamper(stored, 1), KEY, USER_ID)),
      messageOf(() => decryptTotpSecret(tamper(stored, 2), KEY, USER_ID)),
      messageOf(() => decryptTotpSecret(tamper(stored, 3), KEY, USER_ID)),
      messageOf(() => decryptTotpSecret('v2.aaa.bbb.ccc', KEY, USER_ID)),
      messageOf(() => decryptTotpSecret('garbage', KEY, USER_ID)),
      messageOf(() => decryptTotpSecret(stored, Buffer.alloc(8, 1), USER_ID)),
    ];

    expect(new Set(messages)).toEqual(new Set(['totp secret unreadable']));
  });
});
