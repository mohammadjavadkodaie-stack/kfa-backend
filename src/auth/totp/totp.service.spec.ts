import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../audit/audit.service';
import type { RateLimitDecision, RateLimitService } from '../../rate-limit/rate-limit.service';
import { InMemoryTotpRepository } from './in-memory-totp.repository';
import { hashRecoveryCode } from './recovery-codes';
import { base32Decode, totpAt } from './totp';
import { InMemoryTotpRotationStore, ROTATION_PENDING_TTL_SECONDS } from './totp-rotation.store';
import { TOTP_VERIFY_USER_LIMIT, TotpService } from './totp.service';

const USER_ID = '6b1f2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d';
const USERNAME = 'ivan';
/** Fixed clock, so every step in these tests is predictable. */
const NOW_MS = 1_780_000_000_000;
const STEP_MS = 30_000;
/** Deterministic, obviously fake key material: 32 bytes in base64url. */
const ENC_KEY = Buffer.alloc(32, 7).toString('base64url');

interface ConsumeInput {
  readonly scope: string;
  readonly identifier: string;
  readonly limit: number;
  readonly windowSeconds: number;
}

interface Counter {
  hits: number;
  expiresAt: number;
}

/**
 * In-memory fixed window with the same semantics as the Redis one, so the tests
 * exercise the real ordering of the checks instead of a scripted mock.
 */
class FakeRateLimit {
  private readonly counters = new Map<string, Counter>();
  readonly calls: ConsumeInput[] = [];
  readonly resets: { scope: string; identifier: string }[] = [];
  unavailable = false;
  private now = 0;

  async consume(input: ConsumeInput): Promise<RateLimitDecision> {
    if (this.unavailable) throw new ServiceUnavailableException();

    this.calls.push({ ...input });

    const key = `${input.scope}:${input.identifier}`;
    const current = this.counters.get(key);
    const counter =
      current !== undefined && current.expiresAt > this.now
        ? current
        : { hits: 0, expiresAt: this.now + input.windowSeconds * 1_000 };

    counter.hits += 1;
    this.counters.set(key, counter);

    const allowed = counter.hits <= input.limit;

    return {
      allowed,
      remaining: Math.max(0, input.limit - counter.hits),
      retryAfterSeconds: allowed ? 0 : Math.ceil((counter.expiresAt - this.now) / 1_000),
    };
  }

  async reset(input: { scope: string; identifier: string }): Promise<void> {
    if (this.unavailable) throw new ServiceUnavailableException();

    this.resets.push({ ...input });
    this.counters.delete(`${input.scope}:${input.identifier}`);
  }

  advance(seconds: number): void {
    this.now += seconds * 1_000;
  }

  hits(scope: string, identifier: string): number {
    return this.counters.get(`${scope}:${identifier}`)?.hits ?? 0;
  }
}

function createHarness(options: { encKey?: string | null } = {}) {
  const repository = new InMemoryTotpRepository();
  const rotationClock = { now: 0 };
  const rotations = new InMemoryTotpRotationStore(() => rotationClock.now);
  const rateLimit = new FakeRateLimit();
  const audit = { record: jest.fn().mockResolvedValue(undefined) };
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn() };
  const service = new TotpService(
    { TOTP_ENC_KEY: options.encKey === null ? undefined : (options.encKey ?? ENC_KEY) },
    repository,
    rotations,
    rateLimit as unknown as RateLimitService,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, repository, rotations, rotationClock, rateLimit, audit, logger };
}

type Harness = ReturnType<typeof createHarness>;

interface Enrolled {
  readonly harness: Harness;
  readonly secret: Buffer;
  readonly codes: string[];
}

/** Enrolls and confirms with the code of the current step. */
async function enroll(): Promise<Enrolled> {
  const harness = createHarness();
  const start = await harness.service.startEnrollment(USER_ID, USERNAME);
  const secret = base32Decode(start.secretBase32);
  const confirmation = await harness.service.confirmEnrollment(
    USER_ID,
    totpAt(secret, NOW_MS),
    NOW_MS,
  );

  if (confirmation.outcome !== 'confirmed') throw new Error('enrollment was refused');

  return { harness, secret, codes: confirmation.recoveryCodes };
}

function codeAt(secret: Buffer, offsetSteps = 0): string {
  return totpAt(secret, NOW_MS + offsetSteps * STEP_MS);
}

/** A code that is certainly not the valid one, so a test cannot flake. */
function wrongCode(secret: Buffer): string {
  return codeAt(secret) === '000000' ? '000001' : '000000';
}

function recordedActions(audit: Harness['audit']): string[] {
  return audit.record.mock.calls.map((call) => (call[0] as { action: string }).action);
}

function stepOf(nowMs: number): number {
  return Math.floor(nowMs / 1_000 / 30);
}

describe('TotpService enrollment', () => {
  it('enrolls, confirms and verifies a code', async () => {
    const harness = createHarness();
    const start = await harness.service.startEnrollment(USER_ID, USERNAME);
    const secret = base32Decode(start.secretBase32);

    expect(start.otpauthUri).toContain(`otpauth://totp/KFA:${USERNAME}`);
    expect(start.otpauthUri).toContain(`secret=${start.secretBase32}`);

    // The secret leaves the service here and nowhere else.
    const stored = await harness.repository.getCredential(USER_ID);
    expect(stored).not.toBeNull();
    expect(stored?.confirmedAt).toBeNull();
    expect(stored?.secretEnc.startsWith('v1.')).toBe(true);
    expect(stored?.secretEnc).not.toContain(start.secretBase32);

    const confirmation = await harness.service.confirmEnrollment(USER_ID, codeAt(secret), NOW_MS);

    expect(confirmation.outcome).toBe('confirmed');

    if (confirmation.outcome !== 'confirmed') return;

    expect(confirmation.recoveryCodes).toHaveLength(10);
    expect(confirmation.recoveryCodes[0]).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    // The step of the confirming code is spent, so it can never be replayed.
    expect((await harness.repository.getCredential(USER_ID))?.lastUsedStep).toBe(stepOf(NOW_MS));

    await expect(
      harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: true, method: 'totp' });

    expect(recordedActions(harness.audit)).toEqual(['totp.enrolled']);
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(10);
  });

  it('rejects a code that was already used', async () => {
    const { harness, secret } = await enroll();
    const code = codeAt(secret, 1);

    await expect(harness.service.verifyCode(USER_ID, code, NOW_MS + STEP_MS)).resolves.toEqual({
      ok: true,
      method: 'totp',
    });
    await expect(harness.service.verifyCode(USER_ID, code, NOW_MS + STEP_MS)).resolves.toEqual({
      ok: false,
    });
  });

  it('accepts the previous step once, then refuses it after a newer one', async () => {
    const { harness, secret } = await enroll();
    const later = NOW_MS + 2 * STEP_MS;

    // Two steps have passed, so the step before the current one is unused.
    await expect(harness.service.verifyCode(USER_ID, codeAt(secret, 1), later)).resolves.toEqual({
      ok: true,
      method: 'totp',
    });
    await expect(harness.service.verifyCode(USER_ID, codeAt(secret, 2), later)).resolves.toEqual({
      ok: true,
      method: 'totp',
    });
    await expect(harness.service.verifyCode(USER_ID, codeAt(secret, 1), later)).resolves.toEqual({
      ok: false,
    });
  });

  it('refuses a second enrollment and keeps the stored secret', async () => {
    const { harness } = await enroll();
    const before = await harness.repository.getCredential(USER_ID);

    await expect(harness.service.startEnrollment(USER_ID, USERNAME)).rejects.toBeInstanceOf(
      ConflictException,
    );

    const after = await harness.repository.getCredential(USER_ID);
    expect(after?.secretEnc).toBe(before?.secretEnc);
    expect(after?.confirmedAt).toEqual(before?.confirmedAt);
  });

  it('keeps the pending row when confirmation uses a wrong code', async () => {
    const harness = createHarness();
    const start = await harness.service.startEnrollment(USER_ID, USERNAME);
    const secret = base32Decode(start.secretBase32);
    const pending = await harness.repository.getCredential(USER_ID);

    await expect(
      harness.service.confirmEnrollment(USER_ID, wrongCode(secret), NOW_MS),
    ).resolves.toEqual({ outcome: 'rejected' });

    const after = await harness.repository.getCredential(USER_ID);
    expect(after?.confirmedAt).toBeNull();
    expect(after?.secretEnc).toBe(pending?.secretEnc);
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(0);
  });

  it('cannot verify before the enrollment is confirmed', async () => {
    const harness = createHarness();
    const start = await harness.service.startEnrollment(USER_ID, USERNAME);
    const secret = base32Decode(start.secretBase32);

    await expect(harness.service.verifyCode(USER_ID, codeAt(secret), NOW_MS)).resolves.toEqual({
      ok: false,
    });
    expect(recordedActions(harness.audit)).toEqual([]);
  });
});

describe('TotpService lockout', () => {
  it('refuses the correct code after five wrong ones', async () => {
    const { harness, secret } = await enroll();
    const wrong = wrongCode(secret);

    for (let attempt = 0; attempt < TOTP_VERIFY_USER_LIMIT.limit; attempt += 1) {
      await expect(harness.service.verifyCode(USER_ID, wrong, NOW_MS)).resolves.toEqual({
        ok: false,
      });
    }

    // The sixth attempt is denied before any crypto work, even with a valid code.
    await expect(harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS)).resolves.toEqual({
      ok: false,
    });
    // ... and it did not spend the step, so the user can retry once unlocked.
    expect((await harness.repository.getCredential(USER_ID))?.lastUsedStep).toBe(stepOf(NOW_MS));

    // One lock row per window, however many attempts are refused inside it.
    await expect(harness.service.verifyCode(USER_ID, wrong, NOW_MS)).resolves.toEqual({
      ok: false,
    });
    expect(
      recordedActions(harness.audit).filter((action) => action === 'totp.locked'),
    ).toHaveLength(1);
  });

  it('accepts a fresh code once the lock window has passed', async () => {
    const { harness, secret } = await enroll();
    const wrong = wrongCode(secret);

    for (let attempt = 0; attempt < TOTP_VERIFY_USER_LIMIT.limit; attempt += 1) {
      await harness.service.verifyCode(USER_ID, wrong, NOW_MS);
    }

    harness.rateLimit.advance(TOTP_VERIFY_USER_LIMIT.windowSeconds);

    const later = NOW_MS + TOTP_VERIFY_USER_LIMIT.windowSeconds * 1_000;

    await expect(
      harness.service.verifyCode(USER_ID, totpAt(secret, later), later),
    ).resolves.toEqual({ ok: true, method: 'totp' });
  });

  it('resets the wrong-code budget after a success', async () => {
    const { harness, secret } = await enroll();
    const wrong = wrongCode(secret);

    for (let attempt = 0; attempt < TOTP_VERIFY_USER_LIMIT.limit - 1; attempt += 1) {
      await harness.service.verifyCode(USER_ID, wrong, NOW_MS);
    }

    await expect(harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS)).resolves.toEqual({
      ok: true,
      method: 'totp',
    });
    // The success cleared the budget instead of leaving one attempt to go.
    expect(harness.rateLimit.hits('totp-verify-user', USER_ID)).toBe(0);
  });
});

describe('TotpService recovery codes', () => {
  it('accepts a recovery code once and audits it without leaking it', async () => {
    const { harness, codes } = await enroll();
    const recoveryCode = codes[0] as string;

    await expect(harness.service.verifyCode(USER_ID, recoveryCode, NOW_MS)).resolves.toEqual({
      ok: true,
      method: 'recovery',
    });
    await expect(harness.service.verifyCode(USER_ID, recoveryCode, NOW_MS)).resolves.toEqual({
      ok: false,
    });

    const call = harness.audit.record.mock.calls.find(
      (entry) => (entry[0] as { action: string }).action === 'totp.recovery_used',
    );

    expect(call).toBeDefined();

    const input = call?.[0] as { actorId: string; metadata: Record<string, number> };

    expect(input.actorId).toBe(USER_ID);
    expect(input.metadata).toEqual({ remainingRecoveryCodes: 9 });

    // Neither the code nor its stored hash may appear in the audit details.
    const serialized = JSON.stringify(call);
    const hash = hashRecoveryCode(recoveryCode, Buffer.from(ENC_KEY, 'base64url'));

    expect(serialized).not.toContain(recoveryCode);
    expect(serialized).not.toContain(hash);
  });

  it('accepts a recovery code typed without its dash', async () => {
    const { harness, codes } = await enroll();
    const compact = (codes[1] as string).replace('-', '').toLowerCase();

    await expect(harness.service.verifyCode(USER_ID, compact, NOW_MS)).resolves.toEqual({
      ok: true,
      method: 'recovery',
    });
  });
});

describe('TotpService failure uniformity', () => {
  it('answers every failure kind with the identical object', async () => {
    const { harness, secret } = await enroll();
    const results: unknown[] = [];

    // Unknown user, malformed input, a non-string and a replayed confirm code.
    results.push(await harness.service.verifyCode(randomUUID(), codeAt(secret), NOW_MS));
    results.push(await harness.service.verifyCode(USER_ID, 'not-a-code', NOW_MS));
    results.push(await harness.service.verifyCode(USER_ID, 123456, NOW_MS));
    results.push(await harness.service.verifyCode(USER_ID, codeAt(secret), NOW_MS));

    // A pending enrollment and a wrong code.
    const pendingId = randomUUID();
    await harness.service.startEnrollment(pendingId, 'pending');
    results.push(await harness.service.verifyCode(pendingId, '000000', NOW_MS));
    results.push(await harness.service.verifyCode(USER_ID, wrongCode(secret), NOW_MS));

    // Exhausted budget: the lockout answer is the same one.
    for (let attempt = 0; attempt < TOTP_VERIFY_USER_LIMIT.limit; attempt += 1) {
      await harness.service.verifyCode(USER_ID, wrongCode(secret), NOW_MS);
    }

    results.push(await harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS));

    expect(results).toHaveLength(7);

    for (const result of results) {
      expect(result).toEqual({ ok: false });
    }
  });
});

describe('TotpService fail-closed', () => {
  it('rejects the attempt when the limiter is down', async () => {
    const harness = createHarness();
    const start = await harness.service.startEnrollment(USER_ID, USERNAME);
    const secret = base32Decode(start.secretBase32);

    harness.rateLimit.unavailable = true;

    await expect(
      harness.service.verifyCode(USER_ID, codeAt(secret), NOW_MS),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(
      harness.service.confirmEnrollment(USER_ID, codeAt(secret), NOW_MS),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect((await harness.repository.getCredential(USER_ID))?.confirmedAt).toBeNull();
  });

  const KEY_CASES: [string, string | null][] = [
    ['missing', null],
    ['not 32 bytes', 'AAAA'],
  ];

  it.each(KEY_CASES)('rejects every method when TOTP_ENC_KEY is %s', async (_label, encKey) => {
    const harness = createHarness({ encKey });

    await expect(harness.service.startEnrollment(USER_ID, USERNAME)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    await expect(
      harness.service.confirmEnrollment(USER_ID, '123456', NOW_MS),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(harness.service.verifyCode(USER_ID, '123456', NOW_MS)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    await expect(harness.service.startRotation(USER_ID, USERNAME)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    await expect(harness.service.confirmRotation(USER_ID, '123456', NOW_MS)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    // Fail closed without a side effect: no row, no limiter call, no audit row.
    expect(harness.repository.credentials.size).toBe(0);
    expect(harness.rateLimit.calls).toEqual([]);
    expect(harness.audit.record).not.toHaveBeenCalled();
  });

  it('stores a ciphertext that is useless on another account', async () => {
    const harness = createHarness();
    const start = await harness.service.startEnrollment(USER_ID, USERNAME);
    const secret = base32Decode(start.secretBase32);
    const stored = await harness.repository.getCredential(USER_ID);

    if (stored === null) throw new Error('credential missing');

    expect(stored.secretEnc).not.toContain(start.secretBase32);

    // The user id is the AAD, so a copied envelope no longer decrypts.
    const otherId = randomUUID();

    await harness.repository.saveUnconfirmed(otherId, stored.secretEnc);
    await expect(
      harness.service.confirmEnrollment(otherId, codeAt(secret), NOW_MS),
    ).resolves.toEqual({ outcome: 'rejected' });

    expect((await harness.repository.getCredential(otherId))?.confirmedAt).toBeNull();
  });
});

describe('TotpService rotation', () => {
  it('keeps the active factor and its recovery codes while a replacement is pending', async () => {
    const { harness, secret, codes } = await enroll();
    const before = await harness.repository.getCredential(USER_ID);
    const start = await harness.service.startRotation(USER_ID, USERNAME);

    expect(start.otpauthUri).toContain(`otpauth://totp/KFA:${USERNAME}`);
    expect(start.otpauthUri).toContain(`secret=${start.secretBase32}`);
    expect(base32Decode(start.secretBase32)).not.toEqual(secret);

    // The pending value is ciphertext, bound to the ciphertext it replaces.
    const pending = await harness.rotations.read(USER_ID);
    expect(pending?.secretEnc).not.toContain(start.secretBase32);
    expect(pending?.expectedSecretEnc).toBe(before?.secretEnc);

    // Nothing about the active credential moved.
    const during = await harness.repository.getCredential(USER_ID);
    expect(during?.secretEnc).toBe(before?.secretEnc);
    expect(during?.lastUsedStep).toBe(before?.lastUsedStep);

    await expect(
      harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: true, method: 'totp' });
    await expect(harness.service.verifyCode(USER_ID, codes[0], NOW_MS + STEP_MS)).resolves.toEqual({
      ok: true,
      method: 'recovery',
    });
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(9);
  });

  it('counts a wrong rotation code as an attempt and leaves the active factor alone', async () => {
    const { harness, secret } = await enroll();
    const start = await harness.service.startRotation(USER_ID, USERNAME);
    const next = base32Decode(start.secretBase32);
    const before = await harness.repository.getCredential(USER_ID);
    const activeHashes = (harness.repository.recoveryCodes.get(USER_ID) ?? []).map(
      (code) => code.codeHash,
    );

    await expect(
      harness.service.confirmRotation(USER_ID, wrongCode(next), NOW_MS),
    ).resolves.toEqual({ outcome: 'rejected' });

    const after = await harness.repository.getCredential(USER_ID);
    expect(after?.secretEnc).toBe(before?.secretEnc);
    expect(
      (harness.repository.recoveryCodes.get(USER_ID) ?? []).map((code) => code.codeHash),
    ).toEqual(activeHashes);
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(10);

    // The wrong answer spent exactly one attempt of the shared budget.
    expect(harness.rateLimit.hits('totp-verify-user', USER_ID)).toBe(1);

    // The pending replacement survives a wrong attempt and the old factor works.
    await expect(
      harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: true, method: 'totp' });
  });

  it('swaps in the replacement with ten fresh single-use recovery codes', async () => {
    const { harness, secret, codes } = await enroll();
    const before = await harness.repository.getCredential(USER_ID);
    const start = await harness.service.startRotation(USER_ID, USERNAME);
    const next = base32Decode(start.secretBase32);
    const rotation = await harness.service.confirmRotation(USER_ID, codeAt(next), NOW_MS);

    expect(rotation.outcome).toBe('rotated');

    if (rotation.outcome !== 'rotated') return;

    expect(rotation.recoveryCodes).toHaveLength(10);
    expect(new Set(rotation.recoveryCodes).size).toBe(10);

    for (const code of rotation.recoveryCodes) {
      expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    }

    const after = await harness.repository.getCredential(USER_ID);
    expect(after?.secretEnc).not.toBe(before?.secretEnc);
    expect(after?.confirmedAt).toBeInstanceOf(Date);
    expect(after?.lastUsedStep).toBe(stepOf(NOW_MS));
    // The pending value is gone, so a second confirm starts from nothing.
    expect(await harness.rotations.read(USER_ID)).toBeNull();
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(10);

    // The old authenticator and every old recovery code are worthless now.
    await expect(
      harness.service.verifyCode(USER_ID, codeAt(secret, 1), NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: false });
    await expect(harness.service.verifyCode(USER_ID, codes[0], NOW_MS + STEP_MS)).resolves.toEqual({
      ok: false,
    });

    // The replacement works, and each new recovery code works once.
    await expect(
      harness.service.verifyCode(USER_ID, codeAt(next, 1), NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: true, method: 'totp' });
    await expect(
      harness.service.verifyCode(USER_ID, rotation.recoveryCodes[0], NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: true, method: 'recovery' });
    await expect(
      harness.service.verifyCode(USER_ID, rotation.recoveryCodes[0], NOW_MS + STEP_MS),
    ).resolves.toEqual({ ok: false });
    expect(await harness.repository.countUnusedRecoveryCodes(USER_ID)).toBe(9);
  });

  it('refuses an expired replacement and keeps the active factor', async () => {
    const { harness } = await enroll();
    const before = await harness.repository.getCredential(USER_ID);
    const start = await harness.service.startRotation(USER_ID, USERNAME);
    const next = base32Decode(start.secretBase32);

    harness.rotationClock.now += ROTATION_PENDING_TTL_SECONDS * 1_000;

    await expect(harness.service.confirmRotation(USER_ID, codeAt(next), NOW_MS)).resolves.toEqual({
      outcome: 'rejected',
    });
    expect((await harness.repository.getCredential(USER_ID))?.secretEnc).toBe(before?.secretEnc);
  });

  it('lets a second start replace the first pending secret', async () => {
    const { harness } = await enroll();
    const first = await harness.service.startRotation(USER_ID, USERNAME);
    const second = await harness.service.startRotation(USER_ID, USERNAME);
    const firstSecret = base32Decode(first.secretBase32);
    const secondSecret = base32Decode(second.secretBase32);

    expect(first.secretBase32).not.toBe(second.secretBase32);
    await expect(
      harness.service.confirmRotation(USER_ID, codeAt(firstSecret), NOW_MS),
    ).resolves.toEqual({ outcome: 'rejected' });
    const confirmation = await harness.service.confirmRotation(
      USER_ID,
      codeAt(secondSecret),
      NOW_MS,
    );

    expect(confirmation.outcome).toBe('rotated');
  });

  it('refuses to start a rotation without a confirmed factor', async () => {
    const harness = createHarness();

    await expect(harness.service.startRotation(USER_ID, USERNAME)).rejects.toBeInstanceOf(
      ConflictException,
    );

    // A pending enrollment is not a factor yet; it has to be confirmed first.
    await harness.service.startEnrollment(USER_ID, USERNAME);

    await expect(harness.service.startRotation(USER_ID, USERNAME)).rejects.toBeInstanceOf(
      ConflictException,
    );
    expect(await harness.rotations.read(USER_ID)).toBeNull();
  });

  it('fails closed when the limiter is down', async () => {
    const { harness } = await enroll();
    const before = await harness.repository.getCredential(USER_ID);
    const start = await harness.service.startRotation(USER_ID, USERNAME);
    const next = base32Decode(start.secretBase32);

    harness.rateLimit.unavailable = true;

    await expect(
      harness.service.confirmRotation(USER_ID, codeAt(next), NOW_MS),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect((await harness.repository.getCredential(USER_ID))?.secretEnc).toBe(before?.secretEnc);
  });
});
