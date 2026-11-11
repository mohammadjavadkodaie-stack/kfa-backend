import { isSensitiveMetadataKey, redactMetadata, REDACTED_VALUE } from './audit-redaction';

describe('redactMetadata', () => {
  it('redacts sensitive keys case-insensitively at every depth', () => {
    const result = redactMetadata({
      email: 'user@example.com',
      password: 'p@ssw0rd',
      PASSWORD_HASH: 'bcrypt',
      profile: {
        otp: '123456',
        token: 'bearer-xyz',
        refreshToken: 'refresh-xyz',
        secret: 'shh',
        idNumber: 'AB123456',
        cardNumber: '4111111111111111',
      },
    });

    expect(result).toEqual({
      email: REDACTED_VALUE,
      password: REDACTED_VALUE,
      PASSWORD_HASH: REDACTED_VALUE,
      profile: {
        otp: REDACTED_VALUE,
        token: REDACTED_VALUE,
        refreshToken: REDACTED_VALUE,
        secret: REDACTED_VALUE,
        idNumber: REDACTED_VALUE,
        cardNumber: REDACTED_VALUE,
      },
    });
  });

  it('redacts email and every password variant at any depth', () => {
    const result = redactMetadata({
      email: 'user@example.com',
      emailCode: '123456',
      newPassword: 'new-p@ssw0rd',
      currentPassword: 'current-p@ssw0rd',
      passwordHash: 'bcrypt-hash',
      password_hash: 'bcrypt-hash',
      nested: { deeper: { EMAIL: 'other@example.com', email_code: '654321' } },
      attempts: [{ email: 'third@example.com' }],
    });

    expect(result).toEqual({
      email: REDACTED_VALUE,
      emailCode: REDACTED_VALUE,
      newPassword: REDACTED_VALUE,
      currentPassword: REDACTED_VALUE,
      passwordHash: REDACTED_VALUE,
      password_hash: REDACTED_VALUE,
      nested: { deeper: { EMAIL: REDACTED_VALUE, email_code: REDACTED_VALUE } },
      attempts: [{ email: REDACTED_VALUE }],
    });
  });

  it('redacts keys with separators and mixed case', () => {
    const result = redactMetadata({
      refresh_token: 'a',
      'card-number': 'b',
      id_number: 'c',
      verificationCode: 'd',
    }) as Record<string, string>;

    expect(Object.values(result)).toEqual([
      REDACTED_VALUE,
      REDACTED_VALUE,
      REDACTED_VALUE,
      REDACTED_VALUE,
    ]);
  });

  it('redacts nested values inside arrays', () => {
    const result = redactMetadata({
      attempts: [{ password: 'first', ipRegion: 'EU' }, { nested: { token: 'second' } }],
    });

    expect(result).toEqual({
      attempts: [
        { password: REDACTED_VALUE, ipRegion: 'EU' },
        { nested: { token: REDACTED_VALUE } },
      ],
    });
  });

  it('does not mutate the input object', () => {
    const input = { password: 'p@ssw0rd', nested: { otp: '123456' } };
    const snapshot = JSON.parse(JSON.stringify(input)) as typeof input;

    redactMetadata(input);

    expect(input).toEqual(snapshot);
  });

  it('neutralises values JSON cannot represent', () => {
    const result = redactMetadata({
      missing: undefined,
      callback: () => undefined,
      infinite: Number.POSITIVE_INFINITY,
      notANumber: Number.NaN,
      big: 10n,
      createdAt: new Date('2026-01-02T03:04:05.000Z'),
      nothing: null,
    });

    expect(result).toEqual({
      missing: null,
      callback: null,
      infinite: null,
      notANumber: null,
      big: '10',
      createdAt: '2026-01-02T03:04:05.000Z',
      nothing: null,
    });
  });

  it('stops at circular references', () => {
    const input: Record<string, unknown> = { name: 'loop' };
    input.self = input;

    expect(redactMetadata(input)).toEqual({ name: 'loop', self: REDACTED_VALUE });
  });

  it('keeps non-sensitive values intact', () => {
    expect(
      redactMetadata({
        userId: 'abc',
        username: 'ada',
        role: 'ADMIN',
        ok: true,
        count: 3,
      }),
    ).toEqual({
      userId: 'abc',
      username: 'ada',
      role: 'ADMIN',
      ok: true,
      count: 3,
    });
  });

  it('returns null for an absent payload', () => {
    expect(redactMetadata(undefined)).toBeNull();
    expect(redactMetadata(null)).toBeNull();
  });
});

describe('isSensitiveMetadataKey', () => {
  it.each([
    ['password', true],
    ['Password', true],
    ['new_password', true],
    ['refreshToken', true],
    ['access-token', true],
    ['otpCode', true],
    ['cardNumber', true],
    ['idNumber', true],
    ['clientSecret', true],
    ['email', true],
    ['Email', true],
    ['email_code', true],
    ['username', false],
    ['role', false],
    ['requestId', false],
  ])('%s -> %s', (key, expected) => {
    expect(isSensitiveMetadataKey(key)).toBe(expected);
  });
});
