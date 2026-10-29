import {
  DEVICE_KEY_MAX_LENGTH,
  ephemeralDeviceKey,
  hashDeviceKey,
  readDeviceKey,
} from './device-key';

const SECRET = 'unit-test-access-token-secret-0123456789abcdef';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_USER_ID = '22222222-2222-4222-8222-222222222222';

describe('readDeviceKey', () => {
  it('accepts a plain header value', () => {
    expect(readDeviceKey('device-abc')).toBe('device-abc');
  });

  it('takes the first value when the header was repeated', () => {
    expect(readDeviceKey(['first', 'second'])).toBe('first');
  });

  it.each([
    ['a missing header', undefined],
    ['an empty value', ''],
    ['an oversized value', 'a'.repeat(DEVICE_KEY_MAX_LENGTH + 1)],
  ])('returns null for %s', (_label, value) => {
    expect(readDeviceKey(value)).toBeNull();
  });

  it('accepts a value exactly at the limit', () => {
    const value = 'a'.repeat(DEVICE_KEY_MAX_LENGTH);

    expect(readDeviceKey(value)).toBe(value);
  });
});

describe('hashDeviceKey', () => {
  it('is 64 lowercase hex characters', () => {
    expect(hashDeviceKey(SECRET, USER_ID, 'device-abc')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is stable for the same inputs', () => {
    expect(hashDeviceKey(SECRET, USER_ID, 'device-abc')).toBe(
      hashDeviceKey(SECRET, USER_ID, 'device-abc'),
    );
  });

  it('differs per user so one browser can serve two accounts', () => {
    expect(hashDeviceKey(SECRET, USER_ID, 'device-abc')).not.toBe(
      hashDeviceKey(SECRET, OTHER_USER_ID, 'device-abc'),
    );
  });

  it('differs per device and per secret', () => {
    const baseline = hashDeviceKey(SECRET, USER_ID, 'device-abc');

    expect(hashDeviceKey(SECRET, USER_ID, 'device-xyz')).not.toBe(baseline);
    expect(hashDeviceKey('another-secret-0123456789abcdefghij', USER_ID, 'device-abc')).not.toBe(
      baseline,
    );
  });
});

describe('ephemeralDeviceKey', () => {
  it('is a 43 character random value', () => {
    expect(ephemeralDeviceKey()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('never repeats', () => {
    const keys = new Set(Array.from({ length: 50 }, () => ephemeralDeviceKey()));

    expect(keys.size).toBe(50);
  });
});
