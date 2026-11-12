import { deriveEmailCodeKey } from './email-keys';
import { emailCodeKey, hashEmailCode } from './email-code.hash';

describe('email code hashing', () => {
  const codeKey = deriveEmailCodeKey('test-email-code-secret');

  it('is deterministic', () => {
    expect(emailCodeKey(codeKey, 'login', 'user@example.com')).toBe(
      emailCodeKey(codeKey, 'login', 'user@example.com'),
    );
    expect(hashEmailCode(codeKey, 'login', 'user@example.com', '123456')).toBe(
      hashEmailCode(codeKey, 'login', 'user@example.com', '123456'),
    );
  });

  it('changes when purpose, email, or code changes', () => {
    const values = [
      emailCodeKey(codeKey, 'login', 'user@example.com'),
      emailCodeKey(codeKey, 'signup', 'user@example.com'),
      emailCodeKey(codeKey, 'login', 'other@example.com'),
      hashEmailCode(codeKey, 'login', 'user@example.com', '123456'),
      hashEmailCode(codeKey, 'signup', 'user@example.com', '123456'),
      hashEmailCode(codeKey, 'login', 'other@example.com', '123456'),
      hashEmailCode(codeKey, 'login', 'user@example.com', '654321'),
    ];

    expect(new Set(values).size).toBe(values.length);
  });

  it('never includes the raw email in the Redis key', () => {
    const email = 'user@example.com';

    expect(emailCodeKey(codeKey, 'login', email)).not.toContain(email);
  });
});
