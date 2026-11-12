import { UnauthorizedException } from '@nestjs/common';
import { EmailAuthService } from './email-auth.service';
const base = {
  email: 'ivan@example.com',
  password: 'correct',
  deviceKey: 'd1',
  proof: null,
  ip: '1.1.1.1',
  userAgent: 'ua',
};
function h() {
  const a = {
    id: 'u',
    username: 'i',
    status: 'ACTIVE' as const,
    role: 'USER' as const,
    passwordHash: 'h',
    emailVerifiedAt: new Date(),
  };
  const auth = {
    hashEmailDeviceKey: jest.fn().mockReturnValue('dh'),
    issueEmailLoginSession: jest.fn().mockResolvedValue({ outcome: 'issued', credentials: {} }),
    auditEmailLoginBlocked: jest.fn(),
  };
  const proof = { consumeEmailProof: jest.fn().mockResolvedValue(base.email) };
  const password = {
    verify: jest.fn().mockResolvedValue(true),
    verifyDummy: jest.fn(),
    needsRehash: jest.fn().mockReturnValue(false),
    hash: jest.fn().mockResolvedValue('new'),
  };
  const rl = {
    consume: jest.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
    peek: jest.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
  };
  const s = {
    findUserByEmail: jest.fn().mockResolvedValue(a),
    isKnownDevice: jest.fn().mockResolvedValue(true),
    updatePasswordHash: jest.fn(),
  };
  const code = { startForVerifiedUser: jest.fn() };
  const service = new EmailAuthService(
    auth as never,
    proof as never,
    password as never,
    rl as never,
    s as never,
    code as never,
  );
  return { service, a, auth, proof, password, rl, s, code };
}
const go = (x: ReturnType<typeof h>, o = {}) => x.service.signIn({ ...base, ...o });
describe('EmailAuthService.signIn', () => {
  it('known device succeeds', async () => {
    const x = h();
    await expect(go(x)).resolves.toMatchObject({ outcome: 'issued' });
    expect(x.code.startForVerifiedUser).not.toHaveBeenCalled();
  });
  it('new device challenges once', async () => {
    const x = h();
    x.s.isKnownDevice.mockResolvedValue(false);
    await expect(go(x)).rejects.toMatchObject({
      status: 403,
      response: { error: 'device_verification_required' },
    });
    expect(x.code.startForVerifiedUser).toHaveBeenCalledTimes(1);
  });
  it('no key challenges', async () => {
    const x = h();
    await expect(go(x, { deviceKey: null })).rejects.toMatchObject({ status: 403 });
  });
  it('valid proof succeeds', async () => {
    const x = h();
    x.s.isKnownDevice.mockResolvedValue(false);
    await expect(go(x, { proof: 'p' })).resolves.toMatchObject({ outcome: 'issued' });
    expect(x.proof.consumeEmailProof).toHaveBeenCalledWith({ proof: 'p', purpose: 'login_device' });
  });
  it.each(['other', 'wrong-purpose', 'reused', 'expired'])('bad proof %s is 401', async (z) => {
    const x = h();
    x.s.isKnownDevice.mockResolvedValue(false);
    x.proof.consumeEmailProof.mockResolvedValue(z === 'other' ? 'other@example.com' : null);
    await expect(go(x, { proof: 'p' })).rejects.toBeInstanceOf(UnauthorizedException);
  });
  it('wrong password verifies once', async () => {
    const x = h();
    x.password.verify.mockResolvedValue(false);
    await expect(go(x)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(x.password.verify).toHaveBeenCalledTimes(1);
  });
  it('unknown uses dummy', async () => {
    const x = h();
    x.s.findUserByEmail.mockResolvedValue(null);
    await expect(go(x)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(x.password.verifyDummy).toHaveBeenCalledTimes(1);
    expect(x.password.verify).not.toHaveBeenCalled();
  });
  it('invalid email uses dummy', async () => {
    const x = h();
    await expect(go(x, { email: 'bad' })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(x.password.verifyDummy).toHaveBeenCalledTimes(1);
  });
  it('blocked audits and rejects', async () => {
    const x = h();
    (x.a as { status: 'ACTIVE' | 'BLOCKED' }).status = 'BLOCKED';
    await expect(go(x)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(x.auth.auditEmailLoginBlocked).toHaveBeenCalled();
  });
  it('rehashes', async () => {
    const x = h();
    x.password.needsRehash.mockReturnValue(true);
    await go(x);
    expect(x.s.updatePasswordHash).toHaveBeenCalledWith('u', 'new');
  });
  it('rehash failure is best effort', async () => {
    const x = h();
    x.password.needsRehash.mockReturnValue(true);
    x.s.updatePasswordHash.mockRejectedValue(new Error());
    await expect(go(x)).resolves.toMatchObject({ outcome: 'issued' });
  });
  it('failure budget checked first', async () => {
    const x = h();
    x.rl.peek.mockResolvedValue({ allowed: false, retryAfterSeconds: 1 });
    await expect(go(x)).rejects.toMatchObject({ status: 429 });
    expect(x.password.verify).not.toHaveBeenCalled();
  });
  it('success has no failure consume', async () => {
    const x = h();
    await go(x);
    expect(x.rl.consume.mock.calls.some(([v]) => String(v.scope).startsWith('signin-fail'))).toBe(
      false,
    );
  });
  it('IP cap rejects', async () => {
    const x = h();
    x.rl.consume.mockImplementation(async (v: { scope: string }) =>
      v.scope === 'signin-ip'
        ? { allowed: false, retryAfterSeconds: 1 }
        : { allowed: true, retryAfterSeconds: 0 },
    );
    await expect(go(x)).rejects.toMatchObject({ status: 429 });
  });
  it('device cap rejects', async () => {
    const x = h();
    x.rl.consume.mockImplementation(async (v: { scope: string }) =>
      v.scope === 'signin-device'
        ? { allowed: false, retryAfterSeconds: 1 }
        : { allowed: true, retryAfterSeconds: 0 },
    );
    await expect(go(x)).rejects.toMatchObject({ status: 429 });
  });
  it('store error propagates', async () => {
    const x = h();
    x.rl.consume.mockRejectedValue(new Error('down'));
    await expect(go(x)).rejects.toThrow('down');
  });
  it('password capacity error propagates', async () => {
    const x = h();
    x.password.verify.mockRejectedValue(new Error('busy'));
    await expect(go(x)).rejects.toThrow('busy');
  });
});
