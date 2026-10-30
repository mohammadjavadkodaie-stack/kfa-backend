import { randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../src/audit/audit.service';
import { PrismaTotpRepository } from '../../src/auth/totp/prisma-totp.repository';
import { InMemoryTotpRotationStore } from '../../src/auth/totp/totp-rotation.store';
import { base32Decode, totpAt } from '../../src/auth/totp/totp';
import { TotpService } from '../../src/auth/totp/totp.service';
import type { PrismaService } from '../../src/database/prisma.service';
import type { RateLimitDecision, RateLimitService } from '../../src/rate-limit/rate-limit.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * The stage 3.2 tables against a real PostgreSQL, as `kfa_app`: the CHECKs, the
 * cascades, the single-statement replay and recovery guards, and the service on
 * top of the Prisma repository.
 */

const hash = () => randomBytes(32).toString('hex');

/** Same shape the secret box produces: a version tag plus base64 payload. */
const envelope = () => `v1:${randomBytes(24).toString('base64')}`;

const unique = (prefix: string) => `${prefix}_${randomUUID().replaceAll('-', '')}`.slice(0, 30);

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '4')
    .slice(0, 7)}`;
}

/** Deterministic, obviously fake key material: 32 bytes in base64url. */
const ENC_KEY = Buffer.alloc(32, 7).toString('base64url');

const STEP_MS = 30_000;
const NOW_MS = 1_780_000_000_000;

/** Verification only needs an admitter here; the counter has its own suites. */
const permissiveLimiter = {
  consume: async (): Promise<RateLimitDecision> => ({
    allowed: true,
    remaining: 99,
    retryAfterSeconds: 0,
  }),
  reset: async (): Promise<void> => undefined,
};

describeWithDatabase('totp persistence (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let repository: PrismaTotpRepository;
  const userIds: string[] = [];

  /** ADMIN, not OWNER: the row trigger only fences the single owner account. */
  const newUser = async (): Promise<string> => {
    const user = await prisma.user.create({
      data: { phone: phone(), username: unique('totp'), role: 'ADMIN' },
    });

    userIds.push(user.id);

    return user.id;
  };

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    repository = new PrismaTotpRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
      await prisma.$disconnect();
    }
  });

  it('rejects a stored secret that is not a v1 envelope', async () => {
    const userId = await newUser();

    for (const secretEnc of ['JBSWY3DPEHPK3PXP', 'v1short', `v2:${'A1b2'.repeat(6)}`]) {
      await expect(prisma.totpCredential.create({ data: { userId, secretEnc } })).rejects.toThrow();
    }

    await expect(prisma.totpCredential.count({ where: { userId } })).resolves.toBe(0);
  });

  it('rejects a recovery hash that is not 64 lowercase hex characters', async () => {
    const userId = await newUser();
    const bad = ['not-a-hash', hash().slice(1), hash().toUpperCase(), 'g'.repeat(64)];

    for (const codeHash of bad) {
      await expect(prisma.recoveryCode.create({ data: { userId, codeHash } })).rejects.toThrow();
    }

    // The real format is accepted, so the rejections above are about the shape.
    await expect(
      prisma.recoveryCode.create({ data: { userId, codeHash: hash() } }),
    ).resolves.toMatchObject({ usedAt: null });
  });

  it('keeps a single credential per user', async () => {
    const userId = await newUser();

    await prisma.totpCredential.create({ data: { userId, secretEnc: envelope() } });

    await expect(
      prisma.totpCredential.create({ data: { userId, secretEnc: envelope() } }),
    ).rejects.toThrow();
    await expect(prisma.totpCredential.count({ where: { userId } })).resolves.toBe(1);
  });

  it('keeps recovery hashes unique per user, not globally', async () => {
    const first = await newUser();
    const second = await newUser();
    const codeHash = hash();

    await prisma.recoveryCode.create({ data: { userId: first, codeHash } });

    await expect(
      prisma.recoveryCode.create({ data: { userId: first, codeHash } }),
    ).rejects.toThrow();
    // Another account may hold the same hash; the index is composite.
    await expect(
      prisma.recoveryCode.create({ data: { userId: second, codeHash } }),
    ).resolves.toBeDefined();
  });

  it('cascades the credential and the codes when the user goes', async () => {
    const userId = await newUser();
    await prisma.totpCredential.create({ data: { userId, secretEnc: envelope() } });
    const code = await prisma.recoveryCode.create({ data: { userId, codeHash: hash() } });

    await prisma.user.delete({ where: { id: userId } });

    await expect(prisma.totpCredential.findUnique({ where: { userId } })).resolves.toBeNull();
    await expect(prisma.recoveryCode.findUnique({ where: { id: code.id } })).resolves.toBeNull();
  });

  it('lets the runtime role read and write both tables', async () => {
    const userId = await newUser();

    const credential = await prisma.totpCredential.create({
      data: { userId, secretEnc: envelope() },
    });
    await expect(
      prisma.totpCredential.update({ where: { userId }, data: { lastUsedStep: 42n } }),
    ).resolves.toMatchObject({ id: credential.id, lastUsedStep: 42n });

    const code = await prisma.recoveryCode.create({ data: { userId, codeHash: hash() } });
    await expect(
      prisma.recoveryCode.update({ where: { id: code.id }, data: { usedAt: new Date() } }),
    ).resolves.toMatchObject({ usedAt: expect.any(Date) as Date });

    await prisma.recoveryCode.delete({ where: { id: code.id } });
    await prisma.totpCredential.delete({ where: { userId } });

    await expect(prisma.recoveryCode.count({ where: { userId } })).resolves.toBe(0);
    await expect(prisma.totpCredential.count({ where: { userId } })).resolves.toBe(0);
  });

  it('lets exactly one of two parallel advanceStep calls win', async () => {
    const userId = await newUser();
    await prisma.totpCredential.create({
      data: { userId, secretEnc: envelope(), confirmedAt: new Date() },
    });

    const results = await Promise.all([
      repository.advanceStep(userId, 5),
      repository.advanceStep(userId, 5),
    ]);

    expect(results.filter((accepted) => accepted)).toHaveLength(1);
    await expect(repository.getCredential(userId)).resolves.toMatchObject({ lastUsedStep: 5 });
  });

  it('lets exactly one of two parallel consumeRecoveryCode calls win', async () => {
    const userId = await newUser();
    const codeHash = hash();
    await prisma.recoveryCode.create({ data: { userId, codeHash } });

    const results = await Promise.all([
      repository.consumeRecoveryCode(userId, codeHash),
      repository.consumeRecoveryCode(userId, codeHash),
    ]);

    expect(results.filter((used) => used)).toHaveLength(1);
    await expect(repository.countUnusedRecoveryCodes(userId)).resolves.toBe(0);
  });

  it('enrolls, confirms, verifies once and refuses the replay', async () => {
    const userId = await newUser();
    const service = new TotpService(
      { TOTP_ENC_KEY: ENC_KEY },
      repository,
      new InMemoryTotpRotationStore(),
      permissiveLimiter as unknown as RateLimitService,
      { record: async () => undefined } as unknown as AuditService,
      { warn: () => undefined } as unknown as PinoLogger,
    );

    const start = await service.startEnrollment(userId, unique('label'));
    const secret = base32Decode(start.secretBase32);
    const confirmation = await service.confirmEnrollment(userId, totpAt(secret, NOW_MS), NOW_MS);

    if (confirmation.outcome !== 'confirmed') throw new Error('enrollment was refused');

    const nextCode = totpAt(secret, NOW_MS + STEP_MS);

    await expect(service.verifyCode(userId, nextCode, NOW_MS + STEP_MS)).resolves.toEqual({
      ok: true,
      method: 'totp',
    });
    // Same code, same step: the stored step already moved past it.
    await expect(service.verifyCode(userId, nextCode, NOW_MS + STEP_MS)).resolves.toEqual({
      ok: false,
    });

    const stored = await prisma.totpCredential.findUniqueOrThrow({ where: { userId } });

    expect(stored.confirmedAt).toBeInstanceOf(Date);
    // Only the envelope is persisted; the plaintext secret never is.
    expect(stored.secretEnc).toMatch(/^v1/);
    expect(stored.secretEnc).not.toContain(start.secretBase32);
    await expect(repository.countUnusedRecoveryCodes(userId)).resolves.toBe(
      confirmation.recoveryCodes.length,
    );
  });
});
