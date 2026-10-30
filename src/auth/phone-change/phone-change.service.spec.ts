import { BadRequestException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import {
  FakeAudit,
  FakeLogger,
  FakeRateLimit,
  TEST_NOW,
  TEST_OTHER_PHONE,
  TEST_PHONE,
  TEST_SECRET,
  TEST_USERNAME,
  contextWith,
  issued,
  type AuditRecord,
} from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import type { RateLimitService } from '../../rate-limit/rate-limit.service';
import { AuthService, type IssuedCredentials, type SessionPrincipal } from '../auth.service';
import type { CaptchaProvider } from '../captcha';
import { InMemorySessionRepository } from '../in-memory-session.repository';
import type { OtpContext, OtpNotice, OtpProvider } from '../otp/otp.provider';
import { OtpService } from '../otp/otp.service';
import { maskPhone } from '../phone';
import type { ProofPurpose, ProofTokenService } from '../otp/proof-token';
import {
  PHONE_CHANGE_CONFIRM_USER_LIMIT,
  PhoneChangeService,
  type PhoneChangeConfirmResult,
  type PhoneChangeStartResult,
  type PhoneChangeVerifyResult,
} from './phone-change.service';

const CONTEXT = contextWith({ requestId: 'req-phone-change' });
const CAPTCHA = 'captcha-ok';
const CODE = '123456';
const NEW_PHONE = '+14155559999';
const TAKEN_PHONE = '+14155557777';

/** Purpose-bound, single-use stand-in for the signed proofs. */
class FakeProofTokens {
  private readonly tokens = new Map<
    string,
    { readonly phone: string; readonly purpose: ProofPurpose; used: boolean }
  >();
  private counter = 0;

  async issue(phoneE164: string, purpose: ProofPurpose): Promise<string> {
    this.counter += 1;

    const token = `proof-${this.counter}`;
    this.tokens.set(token, { phone: phoneE164, purpose, used: false });

    return token;
  }

  async verifyAndConsumeProof(token: unknown, purpose: ProofPurpose): Promise<string | null> {
    if (typeof token !== 'string') return null;

    const entry = this.tokens.get(token);

    // Wrong purpose and a replay look exactly like an unknown token.
    if (entry === undefined || entry.used || entry.purpose !== purpose) return null;

    entry.used = true;

    return entry.phone;
  }
}

class FakeCaptcha implements CaptchaProvider {
  async verify(token: string): Promise<boolean> {
    return token === CAPTCHA;
  }
}

/** Records every message instead of sending one; can be told to fail. */
class RecordingOtpProvider implements OtpProvider {
  readonly sends: { readonly phone: string; readonly purpose: ProofPurpose }[] = [];
  readonly notices: { readonly phone: string; readonly notice: OtpNotice }[] = [];
  failSend = false;
  failNotice = false;

  async start(phoneE164: string, context: OtpContext): Promise<{ challengeRef: string | null }> {
    if (this.failSend) throw new Error('transport down');

    this.sends.push({ phone: phoneE164, purpose: context.purpose });

    return { challengeRef: null };
  }

  async check(_phoneE164: string, code: string): Promise<boolean> {
    return code === CODE;
  }

  async notify(phoneE164: string, notice: OtpNotice): Promise<void> {
    if (this.failNotice) throw new Error('transport down');

    this.notices.push({ phone: phoneE164, notice });
  }
}

function createHarness() {
  const rateLimit = new FakeRateLimit();
  const audit = new FakeAudit();
  const logger = new FakeLogger();
  const sessions = new InMemorySessionRepository();
  const proof = new FakeProofTokens();
  const provider = new RecordingOtpProvider();

  const otp = new OtpService(
    { OTP_GLOBAL_SENDS_PER_HOUR: 1_000 },
    rateLimit as unknown as RateLimitService,
    proof as unknown as ProofTokenService,
    provider,
    new FakeCaptcha(),
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  const auth = new AuthService(
    {
      ACCESS_TOKEN_SECRET: TEST_SECRET,
      ACCESS_TOKEN_TTL_SECONDS: 600,
      REFRESH_TTL_DAYS: 14,
      SESSION_ABSOLUTE_DAYS: 30,
      STAFF_SESSION_ABSOLUTE_HOURS: 12,
      STAFF_SESSION_IDLE_MINUTES: 30,
      SESSIONS_MAX_PER_USER: 10,
    },
    sessions,
    proof as unknown as ProofTokenService,
    rateLimit as unknown as RateLimitService,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  const service = new PhoneChangeService(
    sessions,
    proof as unknown as ProofTokenService,
    otp,
    provider,
    new FakeCaptcha(),
    rateLimit as unknown as RateLimitService,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, auth, rateLimit, audit, logger, sessions, proof, provider };
}

type Harness = ReturnType<typeof createHarness>;

function principalOf(credentials: IssuedCredentials): SessionPrincipal {
  return { userId: credentials.userId, sessionId: credentials.sessionId };
}

/** Registers an account through the real service, so sessions are real rows. */
async function account(
  harness: Harness,
  phone = TEST_PHONE,
  username = TEST_USERNAME,
): Promise<{ credentials: IssuedCredentials; principal: SessionPrincipal }> {
  const proof = await harness.proof.issue(phone, 'register');
  const credentials = issued(await harness.auth.register({ proof, username }, CONTEXT));

  return { credentials, principal: principalOf(credentials) };
}

function startChange(
  harness: Harness,
  principal: SessionPrincipal,
  phone = NEW_PHONE,
): Promise<PhoneChangeStartResult> {
  return harness.service.start(principal, { phone, captchaToken: CAPTCHA }, CONTEXT);
}

function verified(result: PhoneChangeVerifyResult): string {
  if (result.outcome !== 'verified') {
    throw new Error(`expected a proof, received ${result.outcome}`);
  }

  return result.proof;
}

/** Start plus both codes, the state the confirm step needs. */
async function bothProofs(
  harness: Harness,
  principal: SessionPrincipal,
  phone = NEW_PHONE,
): Promise<{ proofNew: string; proofOld: string }> {
  await startChange(harness, principal, phone);

  return {
    proofNew: verified(await harness.service.verifyNew(principal, { phone, code: CODE }, CONTEXT)),
    proofOld: verified(await harness.service.verifyOld(principal, { code: CODE }, CONTEXT)),
  };
}

function expectChanged(result: PhoneChangeConfirmResult): void {
  if (result.outcome !== 'changed') {
    throw new Error(`expected a change, received ${result.outcome}`);
  }
}

async function phoneOf(harness: Harness, principal: SessionPrincipal): Promise<string | null> {
  return harness.sessions.findPhoneByUserId(principal.userId);
}

function phoneChangeAudit(harness: Harness): AuditRecord[] {
  return harness.audit.records.filter((record) => record.action.includes('phone_change'));
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(TEST_NOW);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('PhoneChangeService.start', () => {
  it('sends one code to the new number and one to the number on the account', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);

    await expect(startChange(harness, principal)).resolves.toEqual({ outcome: 'accepted' });

    expect(harness.provider.sends).toEqual([
      { phone: TEST_PHONE, purpose: 'phone_change_old' },
      { phone: NEW_PHONE, purpose: 'phone_change_new' },
    ]);
    // Nothing changes until both codes are proved.
    await expect(phoneOf(harness, principal)).resolves.toBe(TEST_PHONE);
    expect(phoneChangeAudit(harness)).toMatchObject([
      {
        action: 'auth.phone_change.started',
        actorId: principal.userId,
        targetType: 'user',
      },
    ]);
  });

  it('answers exactly like a free number when the new number is taken', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);

    harness.sessions.seedUser({ phone: TAKEN_PHONE, username: 'taken_user' });

    const taken = await startChange(harness, principal, TAKEN_PHONE);

    harness.rateLimit.reset();

    const free = await startChange(harness, principal, NEW_PHONE);

    expect(taken).toEqual(free);
    expect(taken).toEqual({ outcome: 'accepted' });
    // Only the holder of the current number is told anything.
    expect(harness.provider.sends).toEqual([
      { phone: TEST_PHONE, purpose: 'phone_change_old' },
      { phone: TEST_PHONE, purpose: 'phone_change_old' },
      { phone: NEW_PHONE, purpose: 'phone_change_new' },
    ]);
    expect(phoneChangeAudit(harness)[0]?.metadata).toMatchObject({
      newPhone: maskPhone(TAKEN_PHONE),
      newPhoneTaken: true,
    });
  });

  it('refuses a captcha the provider does not accept', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);

    await expect(
      harness.service.start(principal, { phone: NEW_PHONE, captchaToken: 'nope' }, CONTEXT),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(harness.provider.sends).toHaveLength(0);
  });

  it('refuses a body that carries a purpose or the number already on the account', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);

    await expect(
      harness.service.start(
        principal,
        { phone: NEW_PHONE, captchaToken: CAPTCHA, purpose: 'phone_change_old' },
        CONTEXT,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);

    await expect(startChange(harness, principal, TEST_PHONE)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(harness.provider.sends).toHaveLength(0);
  });

  it('throttles a second start inside the cooldown', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);

    await startChange(harness, principal);

    const second = await startChange(harness, principal, TEST_OTHER_PHONE);

    expect(second).toMatchObject({ outcome: 'throttled' });
    expect(harness.provider.sends).toHaveLength(2);
  });
});

describe('PhoneChangeService.verify', () => {
  it('rejects a wrong code', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    await startChange(harness, principal);

    await expect(
      harness.service.verifyNew(principal, { phone: NEW_PHONE, code: '000000' }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });
    await expect(
      harness.service.verifyOld(principal, { code: '000000' }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });
  });

  it('reads the current number from the account, never from the body', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    await startChange(harness, principal);

    // A body that tries to name the old number is malformed, not a hint.
    await expect(
      harness.service.verifyOld(principal, { code: CODE, phone: TAKEN_PHONE }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });

    await expect(
      harness.service.verifyOld(principal, { code: CODE }, CONTEXT),
    ).resolves.toMatchObject({ outcome: 'verified' });
    expect(harness.provider.sends.map((send) => send.phone)).toEqual([TEST_PHONE, NEW_PHONE]);
  });
});

describe('PhoneChangeService.confirm', () => {
  it('moves the account, keeps the asking session and revokes the others', async () => {
    const harness = createHarness();
    const { credentials, principal } = await account(harness);
    const other = issued(
      await harness.auth.login(
        { proof: await harness.proof.issue(TEST_PHONE, 'login') },
        contextWith({ deviceKey: 'device-2' }),
      ),
    );

    const proofs = await bothProofs(harness, principal);

    await expect(harness.service.confirm(principal, proofs, CONTEXT)).resolves.toEqual({
      outcome: 'changed',
    });

    await expect(phoneOf(harness, principal)).resolves.toBe(NEW_PHONE);
    await expect(
      harness.sessions.findActiveSession(credentials.sessionId, credentials.userId, new Date()),
    ).resolves.not.toBeNull();
    await expect(
      harness.sessions.findActiveSession(other.sessionId, other.userId, new Date()),
    ).resolves.toBeNull();

    // Exactly one message, to the number that lost the account, already masked.
    expect(harness.provider.notices).toEqual([
      { phone: TEST_PHONE, notice: { kind: 'phone_changed', maskedPhone: maskPhone(NEW_PHONE) } },
    ]);
    expect(phoneChangeAudit(harness).map((record) => record.action)).toEqual([
      'auth.phone_change.started',
      'auth.phone_changed',
    ]);
  });

  it('rejects a proof minted for another purpose', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);
    const loginProof = await harness.proof.issue(TEST_PHONE, 'login');

    await expect(
      harness.service.confirm(principal, { ...proofs, proofNew: loginProof }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });
    await expect(
      harness.service.confirm(principal, { ...proofs, proofOld: loginProof }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });
    await expect(phoneOf(harness, principal)).resolves.toBe(TEST_PHONE);
    expect(harness.provider.notices).toHaveLength(0);
  });

  it('rejects a replayed proof pair', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    await expect(harness.service.confirm(principal, proofs, CONTEXT)).resolves.toEqual({
      outcome: 'changed',
    });
    await expect(harness.service.confirm(principal, proofs, CONTEXT)).resolves.toEqual({
      outcome: 'rejected',
    });
    expect(harness.provider.notices).toHaveLength(1);
  });

  it('rejects a current-number proof that belongs to another number', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);
    const foreignOld = await harness.proof.issue(TAKEN_PHONE, 'phone_change_old');

    await expect(
      harness.service.confirm(principal, { ...proofs, proofOld: foreignOld }, CONTEXT),
    ).resolves.toEqual({ outcome: 'rejected' });
    await expect(phoneOf(harness, principal)).resolves.toBe(TEST_PHONE);
  });

  it('rejects the change when somebody else takes the number after the codes', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    harness.sessions.seedUser({ phone: NEW_PHONE, username: 'squatter' });

    await expect(harness.service.confirm(principal, proofs, CONTEXT)).resolves.toEqual({
      outcome: 'rejected',
    });
    await expect(phoneOf(harness, principal)).resolves.toBe(TEST_PHONE);
    expect(harness.provider.notices).toHaveLength(0);
  });

  it('lets exactly one of two parallel confirms win', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    const results = await Promise.all([
      harness.service.confirm(principal, proofs, CONTEXT),
      harness.service.confirm(principal, proofs, CONTEXT),
    ]);

    expect(results.map((result) => result.outcome).sort()).toEqual(['changed', 'rejected']);
    await expect(phoneOf(harness, principal)).resolves.toBe(NEW_PHONE);
    expect(harness.provider.notices).toHaveLength(1);
  });

  it('still changes the number when the notice cannot be sent', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    harness.provider.failNotice = true;

    expectChanged(await harness.service.confirm(principal, proofs, CONTEXT));

    await expect(phoneOf(harness, principal)).resolves.toBe(NEW_PHONE);
    expect(phoneChangeAudit(harness).map((record) => record.action)).toEqual([
      'auth.phone_change.started',
      'auth.phone_changed',
      'auth.phone_change.notice_failed',
    ]);
    expect(harness.logger.warns.length).toBeGreaterThan(0);
  });

  it('never writes a full phone number into the audit trail', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    expectChanged(await harness.service.confirm(principal, proofs, CONTEXT));

    const trail = JSON.stringify(phoneChangeAudit(harness));

    expect(trail).not.toContain(TEST_PHONE);
    expect(trail).not.toContain(NEW_PHONE);
    expect(trail).toContain(maskPhone(NEW_PHONE));
  });

  it('throttles once the confirm budget is spent', async () => {
    const harness = createHarness();
    const { principal } = await account(harness);
    const proofs = await bothProofs(harness, principal);

    harness.rateLimit.seed(
      'phone-change-confirm-user',
      principal.userId,
      PHONE_CHANGE_CONFIRM_USER_LIMIT.limit,
      PHONE_CHANGE_CONFIRM_USER_LIMIT.windowSeconds,
    );

    const result = await harness.service.confirm(principal, proofs, CONTEXT);

    expect(result).toMatchObject({ outcome: 'throttled' });
    await expect(phoneOf(harness, principal)).resolves.toBe(TEST_PHONE);
  });
});
