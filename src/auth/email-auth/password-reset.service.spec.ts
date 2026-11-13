import { BadRequestException, HttpException, UnauthorizedException } from '@nestjs/common';
import { PasswordResetService } from './password-reset.service';

const EMAIL = 'ivan@example.com';
const STRONG = 'correct horse battery';

const base = { proof: 'p', newPassword: STRONG, ip: '1.1.1.1', requestId: 'r1' };

function h() {
  const account = {
    id: 'u1',
    username: 'ivan',
    role: 'USER' as const,
    status: 'ACTIVE' as const,
    passwordHash: 'scrypt$v1$stored',
    emailVerifiedAt: new Date(),
  };
  const code = { start: jest.fn().mockResolvedValue(undefined) };
  const proof = {
    peekEmailProof: jest.fn().mockResolvedValue(EMAIL),
    consumeEmailProof: jest.fn().mockResolvedValue(EMAIL),
  };
  const password = { hash: jest.fn().mockResolvedValue('scrypt$v1$new') };
  const rl = { consume: jest.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }) };
  const s = {
    findUserByEmail: jest.fn().mockResolvedValue(account),
    updatePasswordHash: jest.fn().mockResolvedValue(undefined),
    revokeAllUserSessions: jest.fn().mockResolvedValue(undefined),
  };
  const email = { sendNotice: jest.fn().mockResolvedValue(undefined) };
  const audit = { record: jest.fn().mockResolvedValue({}) };
  const logger = { info: jest.fn(), warn: jest.fn() };
  const service = new PasswordResetService(
    code as never,
    proof as never,
    password as never,
    rl as never,
    s as never,
    email as never,
    audit as never,
    logger as never,
  );

  return { service, account, code, proof, password, rl, s, email, audit, logger };
}

const go = (x: ReturnType<typeof h>, o = {}) => x.service.reset({ ...base, ...o });

describe('PasswordResetService.start', () => {
  it('mails a reset code for an account that has a password', async () => {
    const x = h();

    await expect(
      x.service.start({ email: EMAIL, captchaToken: 'c', ip: '1.1.1.1' }),
    ).resolves.toBeUndefined();

    expect(x.code.start).toHaveBeenCalledWith(
      expect.objectContaining({ email: EMAIL, purpose: 'password_reset', eligible: true }),
    );
  });

  it('runs the same work but sends nothing for an unknown address', async () => {
    const x = h();
    x.s.findUserByEmail.mockResolvedValue(null);

    await expect(
      x.service.start({ email: EMAIL, captchaToken: 'c', ip: '1.1.1.1' }),
    ).resolves.toBeUndefined();

    expect(x.code.start).toHaveBeenCalledWith(expect.objectContaining({ eligible: false }));
  });

  it('treats an account without a password as ineligible', async () => {
    const x = h();
    x.s.findUserByEmail.mockResolvedValue({ ...x.account, passwordHash: null });

    await x.service.start({ email: EMAIL, captchaToken: 'c', ip: '1.1.1.1' });

    expect(x.code.start).toHaveBeenCalledWith(expect.objectContaining({ eligible: false }));
  });

  it('rejects an address that cannot be normalized before mailing', async () => {
    const x = h();

    await expect(
      x.service.start({ email: 'not-an-email', captchaToken: 'c', ip: '1.1.1.1' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(x.code.start).not.toHaveBeenCalled();
  });
});

describe('PasswordResetService.reset', () => {
  it('updates the hash, revokes every session, mails once and audits without secrets', async () => {
    const x = h();

    await expect(go(x)).resolves.toBeUndefined();

    expect(x.password.hash).toHaveBeenCalledWith(STRONG);
    expect(x.s.updatePasswordHash).toHaveBeenCalledWith('u1', 'scrypt$v1$new');
    expect(x.s.revokeAllUserSessions).toHaveBeenCalledWith(
      'u1',
      'password_reset',
      expect.any(Date),
    );
    expect(x.email.sendNotice).toHaveBeenCalledWith({ to: EMAIL, kind: 'password_changed' });
    expect(x.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'password.reset', actorId: 'u1', targetId: 'u1' }),
    );

    const trail = JSON.stringify(x.audit.record.mock.calls);
    expect(trail).not.toContain(EMAIL);
    expect(trail).not.toContain(STRONG);
    expect(trail).not.toContain('"p"');

    // The reset must not sign the user in: no credentials were ever issued.
    expect(x.logger.info).toHaveBeenCalled();
  });

  it('refuses a weak password without spending the proof', async () => {
    const x = h();

    await expect(go(x, { newPassword: 'short' })).rejects.toMatchObject({
      status: 400,
      response: { error: 'weak_password', reason: 'too_short' },
    });

    expect(x.proof.consumeEmailProof).not.toHaveBeenCalled();
    expect(x.password.hash).not.toHaveBeenCalled();
    expect(x.s.updatePasswordHash).not.toHaveBeenCalled();
    expect(x.s.revokeAllUserSessions).not.toHaveBeenCalled();
    expect(x.email.sendNotice).not.toHaveBeenCalled();
  });

  it('refuses a password built from the username without spending the proof', async () => {
    const x = h();

    await expect(go(x, { newPassword: 'ivan-ivan-ivan' })).rejects.toMatchObject({
      status: 400,
      response: { error: 'weak_password', reason: 'contains_identity' },
    });

    expect(x.proof.consumeEmailProof).not.toHaveBeenCalled();
  });

  it('answers one generic 401 for an unverifiable proof', async () => {
    const x = h();
    x.proof.peekEmailProof.mockResolvedValue(null);

    await expect(go(x)).rejects.toMatchObject({
      status: 401,
      response: { error: 'invalid_proof' },
    });

    expect(x.s.findUserByEmail).not.toHaveBeenCalled();
    expect(x.s.updatePasswordHash).not.toHaveBeenCalled();
  });

  it('answers the same 401 for an account that disappeared', async () => {
    const x = h();
    x.s.findUserByEmail.mockResolvedValue(null);

    await expect(go(x)).rejects.toMatchObject({
      status: 401,
      response: { error: 'invalid_proof' },
    });
    expect(x.proof.consumeEmailProof).not.toHaveBeenCalled();
  });

  it('answers the same 401 when the proof is spent between the two reads', async () => {
    const x = h();
    x.proof.consumeEmailProof.mockResolvedValue(null);

    const error = await go(x).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(UnauthorizedException);
    expect(x.s.updatePasswordHash).not.toHaveBeenCalled();
    expect(x.s.revokeAllUserSessions).not.toHaveBeenCalled();
  });

  it('keeps the change when the notice cannot be delivered', async () => {
    const x = h();
    x.email.sendNotice.mockRejectedValue(new Error('smtp down'));

    await expect(go(x)).resolves.toBeUndefined();

    expect(x.s.updatePasswordHash).toHaveBeenCalledTimes(1);
    expect(x.s.revokeAllUserSessions).toHaveBeenCalledTimes(1);
    expect(x.audit.record).toHaveBeenCalledTimes(1);
    expect(x.logger.warn).toHaveBeenCalled();
  });

  it('resets a blocked account: the block is enforced at sign-in, not here', async () => {
    const x = h();
    x.s.findUserByEmail.mockResolvedValue({ ...x.account, status: 'BLOCKED' });

    await expect(go(x)).resolves.toBeUndefined();
    expect(x.s.updatePasswordHash).toHaveBeenCalledWith('u1', 'scrypt$v1$new');
  });

  it('throttles before touching the proof', async () => {
    const x = h();
    x.rl.consume.mockResolvedValue({ allowed: false, retryAfterSeconds: 42 });

    const error = await go(x).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getStatus()).toBe(429);
    expect((error as HttpException).getResponse()).toMatchObject({ retryAfterSeconds: 42 });
    expect(x.proof.peekEmailProof).not.toHaveBeenCalled();
  });
});
