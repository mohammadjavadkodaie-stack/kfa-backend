/**
 * Password policy for email + password identities.
 *
 * Deliberately composition-free: length is the only rule that buys real entropy, while
 * "must contain a digit" style rules mostly push users towards "P@ssw0rd1!".
 */

export type PasswordPolicyReason =
  'too_short' | 'too_long' | 'common' | 'contains_identity' | 'repetitive' | 'invalid';

export type PasswordPolicyResult =
  { readonly ok: true } | { readonly ok: false; readonly reason: PasswordPolicyReason };

export interface PasswordIdentityContext {
  readonly email?: string | null;
  readonly username?: string | null;
}

/** Minimum length, counted in Unicode code points (never UTF-16 units). */
export const PASSWORD_MIN_LENGTH = 12;
/** Hard ceiling shared with the hashing service, which refuses to scrypt anything longer. */
export const PASSWORD_MAX_LENGTH = 128;

/** Shorter identity fragments ("abc") match too much of anything to be worth rejecting. */
const IDENTITY_MIN_LENGTH = 4;
/** Runs such as "123456789" or "abcdefgh" are memorable only because they are not secret. */
const SEQUENCE_RUN_LENGTH = 8;
/** Periodic strings ("abcabcabc") with a short period are just as weak. */
const REPEATED_BLOCK_MAX = 8;
/** Cc = control, Cs = unpaired surrogate: neither can survive a round trip through a form. */
const CONTROL_CHARACTERS = /\p{Cc}|\p{Cs}/u;

/**
 * Stopgap denylist of ~150 of the most common passwords (plus the shapes people produce by
 * padding a short one with digits). It is an embedded list, not a breach corpus: swap it for a
 * k-anonymity lookup (HIBP range API) before this identity ships to real users.
 *
 * Only entries of at least PASSWORD_MIN_LENGTH code points can ever match, because everything
 * shorter is already rejected as `too_short` before the lookup runs.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password1234',
  'password12345',
  'password123456',
  'password1234567',
  'password12345678',
  'password123456789',
  'password1234567890',
  'password123!',
  'password123!!',
  'password!2345',
  'passwordpassword',
  'passwordpassword1',
  'passw0rd1234',
  'p@ssw0rd1234',
  'p@ssw0rd!234',
  'p@ssword1234',
  'password1q2w3e',
  'passwort1234',
  'motdepasse12',
  'motdepasse123',
  '123456789012',
  '1234567890123',
  '12345678901234',
  '123456789012345',
  '1234567890123456',
  '12345678901234567',
  '123456789012345678',
  '012345678901',
  '0123456789012',
  '111111111111',
  '000000000000',
  '121212121212',
  '123123123123',
  '112233445566',
  '654321654321',
  '999999999999',
  '888888888888',
  '101010101010',
  '123321123321',
  '123412341234',
  '102030405060',
  '987654321098',
  '1234567890ab',
  '0123456789ab',
  'qwertyuiop123',
  'qwertyuiopasd',
  'qwertyuiopasdf',
  'qwertyuiopasdfg',
  'qwertyuiop12',
  'qwertyuiop1234',
  'qwerty123456',
  'qwerty1234567',
  'qwerty12345678',
  'qwertyuiop!234',
  '1qaz2wsx3edc',
  '1qaz2wsx3edc4rfv',
  'zaq12wsxcde3',
  'zaq1zaq1zaq1',
  'qazwsxedcrfv',
  'qazwsx123456',
  'q1w2e3r4t5y6',
  'q1w2e3r4t5y6u7',
  '1q2w3e4r5t6y',
  '1q2w3e4r5t6y7u',
  'qweasdzxc123',
  'qweasdzxc1234',
  'asdfghjkl123',
  'asdfghjkl1234',
  'zxcvbnm123456',
  'zxcvbnmasdfgh',
  'asdf1234asdf',
  'asdfasdfasdf',
  'qweqweqweqwe',
  'zxcvzxcvzxcv',
  'poiuytrewq123',
  'mnbvcxz12345',
  'iloveyou1234',
  'iloveyou12345',
  'iloveyou123456',
  'iloveyouforever',
  'iloveyoumore',
  'welcome12345',
  'welcome123456',
  'welcome1234567',
  'welcome1welcome',
  'welcome@12345',
  'welcome12345!',
  'monkey123456',
  'dragon123456',
  'letmein12345',
  'letmein123456',
  'football1234',
  'football12345',
  'baseball1234',
  'basketball123',
  'superman1234',
  'sunshine1234',
  'sunshine12345',
  'princess1234',
  'princess12345',
  'shadow123456',
  'master123456',
  'michael12345',
  'jennifer1234',
  'computer1234',
  'internet1234',
  'samsung12345',
  'google123456',
  'facebook1234',
  'instagram123',
  'starwars1234',
  'whatever1234',
  'nothing12345',
  'secret123456',
  'secretpassword',
  'mypassword12',
  'mypassword123',
  'mypassword1234',
  'yourpassword',
  'changeme1234',
  'changeme12345',
  'admin1234567',
  'administrator',
  'rootpassword',
  'defaultpassword',
  'trustno12345',
  'hunter123456',
  'soccer123456',
  'hockey123456',
  'killer123456',
  'banana123456',
  'orange123456',
  'silver123456',
  'summer123456',
  'winter123456',
  'october12345',
  'november12345',
  'december12345',
  'january12345',
  'summer2024!!',
  'summer2025!!',
  'winter2024!!',
  'spring2024!!',
  'autumn2024!!',
  'summer2024!!!',
  'abcd1234abcd',
  'abcd12345678',
  'abcdefg12345',
  'abcdefgh1234',
  'abc123abc123',
  '123abc123abc',
  'passpass1234',
  'passpasspass',
  'letmeinplease',
  'opensesame12',
  'helloworld12',
  'helloworld123',
  'helloworld1234',
  'hellohello12',
  'testtest1234',
  'test1234test',
  'testing12345',
  'testing123456',
  'user12345678',
]);

const ALLOWED: PasswordPolicyResult = { ok: true };

function reject(reason: PasswordPolicyReason): PasswordPolicyResult {
  return { ok: false, reason };
}

/**
 * NFKC first: it folds compatibility forms ("ﬁ" -> "fi", full-width "ｐ" -> "p") so every later
 * comparison sees the characters the user meant to type. Callers must normalize exactly the same
 * way before hashing, otherwise a password that validates may fail to verify.
 */
export function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

function foldIdentity(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    return normalizePassword(value).toLowerCase();
  } catch {
    return null;
  }
}

function emailLocalPart(email: string): string {
  const at = email.lastIndexOf('@');
  return at === -1 ? email : email.slice(0, at);
}

function identityTerms(identity: PasswordIdentityContext): string[] {
  const terms: string[] = [];
  const email = foldIdentity(identity.email);
  if (email !== null) {
    // Only the local part is an identity signal; rejecting a domain would overreach badly.
    terms.push(emailLocalPart(email));
  }
  const username = foldIdentity(identity.username);
  if (username !== null) terms.push(username);
  return terms.filter((term) => Array.from(term).length >= IDENTITY_MIN_LENGTH);
}

function isSingleRepeatedCodePoint(characters: readonly string[]): boolean {
  return characters.every((character) => character === characters[0]);
}

function hasLongSequence(characters: readonly string[]): boolean {
  let direction = 0;
  let run = 1;
  for (let index = 1; index < characters.length; index += 1) {
    const previous = characters[index - 1]?.codePointAt(0) ?? 0;
    const current = characters[index]?.codePointAt(0) ?? 0;
    const step = current - previous;
    const nextDirection = step === 1 ? 1 : step === -1 ? -1 : 0;
    if (nextDirection === 0) {
      direction = 0;
      run = 1;
      continue;
    }
    run = nextDirection === direction ? run + 1 : 2;
    direction = nextDirection;
    if (run >= SEQUENCE_RUN_LENGTH) return true;
  }
  return false;
}

function hasRepeatedBlock(characters: readonly string[]): boolean {
  const maxPeriod = Math.min(REPEATED_BLOCK_MAX, Math.floor(characters.length / 2));
  for (let period = 1; period <= maxPeriod; period += 1) {
    if (characters.length % period !== 0) continue;
    let periodic = true;
    for (let index = period; index < characters.length; index += 1) {
      if (characters[index] !== characters[index - period]) {
        periodic = false;
        break;
      }
    }
    if (periodic) return true;
  }
  return false;
}

function isRepetitive(characters: readonly string[]): boolean {
  return (
    isSingleRepeatedCodePoint(characters) ||
    hasLongSequence(characters) ||
    hasRepeatedBlock(characters)
  );
}

export function validatePassword(
  password: unknown,
  identity: PasswordIdentityContext = {},
): PasswordPolicyResult {
  if (typeof password !== 'string') return reject('invalid');

  let normalized: string;
  try {
    normalized = normalizePassword(password);
  } catch {
    return reject('invalid');
  }
  if (CONTROL_CHARACTERS.test(normalized)) return reject('invalid');

  const characters = Array.from(normalized);
  if (characters.length < PASSWORD_MIN_LENGTH) return reject('too_short');
  if (characters.length > PASSWORD_MAX_LENGTH) return reject('too_long');

  const lowered = normalized.toLowerCase();
  if (COMMON_PASSWORDS.has(lowered)) return reject('common');

  const terms = identityTerms(identity);
  if (terms.some((term) => lowered.includes(term))) return reject('contains_identity');

  return isRepetitive(characters) ? reject('repetitive') : ALLOWED;
}
