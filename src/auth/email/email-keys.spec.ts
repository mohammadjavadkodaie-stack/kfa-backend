import { EmailCodeKeyMissingError, deriveEmailCodeKey, deriveEmailProofKey } from './email-keys';

describe('email key derivation', () => {
  it('is deterministic and separates the two purposes', () => {
    const code = deriveEmailCodeKey('secret-012345678901234567890123');
    expect(deriveEmailCodeKey('secret-012345678901234567890123')).toEqual(code);
    expect(deriveEmailProofKey('secret-012345678901234567890123')).not.toEqual(code);
    expect(code).toHaveLength(32);
  });

  it('throws a typed error when the key is missing', () => {
    expect(() => deriveEmailCodeKey(undefined)).toThrow(EmailCodeKeyMissingError);
    expect(() => deriveEmailProofKey('')).toThrow(EmailCodeKeyMissingError);
  });
});
