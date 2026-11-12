import { ConflictException } from '@nestjs/common';
import { EmailAuthService } from './email-auth.service';
import { PasswordBusyError } from '../password/password.service';

const context = {
  proof: 'proof-token',
  username: 'Ivan_User',
  password: 'a sufficiently strong password',
  deviceKey: 'device-key',
  deviceName: 'Phone',
  ip: '203.0.113.10',
  userAgent: 'test-agent',
} as const;

function createHarness() {
  const auth = {
    issueEmailAccountSession: jest.fn().mockResolvedValue({
      outcome: 'issued',
      credentials: { userId: 'u1', sessionId: 's1' },
    }),
  };
  const proof = { consumeEmailProof: jest.fn().mockResolvedValue('ivan@example.com') };
  const password = { hash: jest.fn().mockResolvedValue('scrypt-hash') };
  const rateLimit = {
    consume: jest.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
  };
  const sessions = {
    isUsernameTaken: jest.fn().mockResolvedValue(false),
    findUserByEmail: jest.fn().mockResolvedValue(null),
  };
  const service = new EmailAuthService(
    auth as never,
    proof as never,
    password as never,
    rateLimit as never,
    sessions as never,
  );
  return { service, auth, proof, password, rateLimit, sessions };
}

describe('EmailAuthService.signUp', () => {
  it('consumes the register proof, hashes the password, and issues the shared session', async () => {
    const harness = createHarness();

    const result = await harness.service.signUp(context);

    expect(result.outcome).toBe('issued');
    expect(harness.proof.consumeEmailProof).toHaveBeenCalledWith({
      proof: 'proof-token',
      purpose: 'register',
    });
    expect(harness.password.hash).toHaveBeenCalledWith(context.password);
    expect(harness.auth.issueEmailAccountSession).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'ivan@example.com',
        username: 'ivan_user',
        passwordHash: 'scrypt-hash',
        deviceName: 'Phone',
      }),
    );
  });

  it('rejects an invalid proof generically and does not hash', async () => {
    const harness = createHarness();
    harness.proof.consumeEmailProof.mockResolvedValue(null);

    await expect(harness.service.signUp(context)).rejects.toMatchObject({
      response: { error: 'invalid_credentials' },
    });
    expect(harness.password.hash).not.toHaveBeenCalled();
  });

  it('returns the password policy reason without creating an account', async () => {
    const harness = createHarness();

    await expect(harness.service.signUp({ ...context, password: 'short' })).rejects.toMatchObject({
      response: { error: 'weak_password', reason: 'too_short' },
    });
    expect(harness.password.hash).not.toHaveBeenCalled();
    expect(harness.auth.issueEmailAccountSession).not.toHaveBeenCalled();
  });

  it('maps a unique race to the generic unavailable conflict', async () => {
    const harness = createHarness();
    harness.auth.issueEmailAccountSession.mockRejectedValue(new ConflictException());

    await expect(harness.service.signUp(context)).rejects.toMatchObject({
      response: { error: 'unavailable' },
    });
  });

  it('returns the rate-limit decision before consuming the proof', async () => {
    const harness = createHarness();
    harness.rateLimit.consume.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });

    await expect(harness.service.signUp(context)).resolves.toEqual({
      outcome: 'throttled',
      retryAfterSeconds: 42,
    });
    expect(harness.proof.consumeEmailProof).not.toHaveBeenCalled();
  });

  it('preserves PasswordBusyError as a 503', async () => {
    const harness = createHarness();
    harness.password.hash.mockRejectedValue(new PasswordBusyError());

    await expect(harness.service.signUp(context)).rejects.toBeInstanceOf(PasswordBusyError);
  });
});
