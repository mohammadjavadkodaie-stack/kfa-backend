import { createHash } from 'node:crypto';
import {
  clearRefreshCookieOptions,
  generateRefreshToken,
  hashRefreshToken,
  isRefreshTokenShaped,
  readCookie,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  refreshCookieLifetimeSeconds,
  refreshCookieOptions,
} from './refresh-token';

const TOKEN = generateRefreshToken();

describe('generateRefreshToken', () => {
  it('produces a 43 character base64url value', () => {
    expect(TOKEN).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('never repeats', () => {
    const tokens = new Set(Array.from({ length: 50 }, () => generateRefreshToken()));

    expect(tokens.size).toBe(50);
  });
});

describe('hashRefreshToken', () => {
  it('is the lowercase hex SHA-256 the database stores', () => {
    expect(hashRefreshToken(TOKEN)).toBe(createHash('sha256').update(TOKEN, 'utf8').digest('hex'));
    expect(hashRefreshToken(TOKEN)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is stable for the same token and different for another one', () => {
    expect(hashRefreshToken(TOKEN)).toBe(hashRefreshToken(TOKEN));
    expect(hashRefreshToken(TOKEN)).not.toBe(hashRefreshToken(generateRefreshToken()));
  });
});

describe('isRefreshTokenShaped', () => {
  it.each([
    ['a real token', TOKEN, true],
    ['a missing value', undefined, false],
    ['empty', '', false],
    ['too short', 'a'.repeat(42), false],
    ['too long', 'a'.repeat(44), false],
    ['illegal characters', 'a'.repeat(42) + '+', false],
    ['a number', 12345, false],
  ])('classifies %s', (_label, value, expected) => {
    expect(isRefreshTokenShaped(value)).toBe(expected);
  });
});

describe('readCookie', () => {
  it('finds its own cookie among others', () => {
    const header = `theme=dark; ${REFRESH_COOKIE_NAME}=${TOKEN}; locale=en`;

    expect(readCookie(header, REFRESH_COOKIE_NAME)).toBe(TOKEN);
  });

  it('tolerates spaces around the name and the value', () => {
    expect(readCookie(`${REFRESH_COOKIE_NAME} = ${TOKEN}`, REFRESH_COOKIE_NAME)).toBe(TOKEN);
  });

  it('ignores cookies that merely end with the name', () => {
    expect(readCookie(`x${REFRESH_COOKIE_NAME}=${TOKEN}`, REFRESH_COOKIE_NAME)).toBeNull();
  });

  it.each([
    ['a missing header', undefined],
    ['an empty header', ''],
    ['an oversized header', `${REFRESH_COOKIE_NAME}=${'a'.repeat(4_096)}`],
    ['no such cookie', 'theme=dark'],
    ['a valueless cookie', `${REFRESH_COOKIE_NAME}=`],
    ['a part without an equals sign', 'broken'],
  ])('returns null for %s', (_label, header) => {
    expect(readCookie(header, REFRESH_COOKIE_NAME)).toBeNull();
  });
});

describe('refreshCookieLifetimeSeconds', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  it('uses the refresh TTL while the session is longer', () => {
    const sessionExpiresAt = new Date(now.getTime() + 30 * 86_400_000);

    expect(refreshCookieLifetimeSeconds(14 * 86_400, sessionExpiresAt, now)).toBe(14 * 86_400);
  });

  it('never outlives the absolute session', () => {
    const sessionExpiresAt = new Date(now.getTime() + 60_000);

    expect(refreshCookieLifetimeSeconds(14 * 86_400, sessionExpiresAt, now)).toBe(60);
  });

  it('is zero once the session has expired', () => {
    const sessionExpiresAt = new Date(now.getTime() - 1_000);

    expect(refreshCookieLifetimeSeconds(14 * 86_400, sessionExpiresAt, now)).toBe(0);
  });
});

describe('cookie options', () => {
  it('marks the refresh cookie as a host-only strict cookie', () => {
    expect(refreshCookieOptions(600)).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: REFRESH_COOKIE_PATH,
      maxAge: 600_000,
    });
  });

  it('clears with the same attributes so the browser actually drops it', () => {
    expect(clearRefreshCookieOptions()).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: REFRESH_COOKIE_PATH,
    });
  });
});
