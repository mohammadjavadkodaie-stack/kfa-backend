import { NotFoundException } from '@nestjs/common';
import type { PrismaClient } from '@prisma/client';
import type { PinoLogger } from 'nestjs-pino';
import { randomBytes } from 'node:crypto';
import { AthleteService, ATHLETE_AUDIT_ACTIONS } from '../../src/athlete/athlete.service';
import type { AthleteProfileInput } from '../../src/athlete/profile/athlete-profile.repository';
import { PrismaAthleteProfileRepository } from '../../src/athlete/profile/prisma-athlete-profile.repository';
import type { PolicySubject } from '../../src/auth/policy/access-policy';
import type { AccessPolicyContext } from '../../src/auth/policy/access-policy.service';
import { ResourceOwnershipService } from '../../src/auth/policy/resource-ownership.service';
import { Role } from '../../src/auth/roles';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestAuditService, createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * Stage 4.1c against a real PostgreSQL, as `kfa_app`: the service over the real
 * repository, the real ownership check and the real hash-chained audit trail.
 *
 * The HTTP contract is proved by `test/athlete-profile.e2e-spec.ts`; here the
 * questions are the ones only the database can answer - one row per athlete
 * however many saves, and no row ever reached through another account.
 */

function phone(): string {
  // Same shape as the other database suites; the random part is padded so the
  // value keeps its length whatever the draw.
  return `+1415${String(randomBytes(4).readUInt32BE(0) % 10_000_000).padStart(7, '0')}`;
}

function username(): string {
  return `athlete_${randomBytes(5).toString('hex')}`;
}

function profile(overrides: Partial<AthleteProfileInput> = {}): AthleteProfileInput {
  return {
    legalFirstName: 'Ada',
    legalLastName: 'Lovelace',
    dateOfBirth: '2001-02-03',
    gender: 'FEMALE',
    nationality: 'PK',
    countryOfResidence: 'SE',
    city: 'Karachi',
    clubName: 'KFA Academy',
    weightKg: 61,
    heightCm: 168,
    ...overrides,
  };
}

/** Refusals are asserted by type: the message is deliberately generic. */
async function refusalOf(call: Promise<unknown>, type: new () => Error): Promise<void> {
  await expect(call).rejects.toBeInstanceOf(type);
}

/** The request facts an audit row may carry. */
function ctx(requestId: string): AccessPolicyContext {
  return { requestId, ip: '203.0.113.7' };
}

describeWithDatabase('athlete profile service (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let service: AthleteService;
  const userIds: string[] = [];
  /** Prints nothing: the warnings of a refused request are not under test here. */
  const logger = {
    warn: (): void => undefined,
    info: (): void => undefined,
  } as unknown as PinoLogger;

  const newAthlete = async (): Promise<PolicySubject> => {
    const user = await prisma.user.create({
      data: { phone: phone(), username: username(), role: Role.ATHLETE },
      select: { id: true },
    });

    userIds.push(user.id);

    return { id: user.id, role: Role.ATHLETE };
  };

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();

    const audit = createTestAuditService(prisma);

    service = new AthleteService(
      new PrismaAthleteProfileRepository(prisma as unknown as PrismaService),
      new ResourceOwnershipService(audit, logger),
      audit,
      logger,
      () => new Date(),
    );
  });

  afterAll(async () => {
    // A profile row only goes away with its account (ON DELETE CASCADE).
    if (prisma) {
      if (userIds.length > 0) {
        await prisma.user.deleteMany({ where: { id: { in: userIds } } });
      }

      await prisma.$disconnect();
    }
  });

  it('keeps one row when the same athlete saves twice', async () => {
    const actor = await newAthlete();

    const created = await service.saveProfile(actor, profile(), ctx('db-athlete-1'));
    const updated = await service.saveProfile(
      actor,
      profile({ city: 'Lahore', clubName: null, weightKg: null }),
      ctx('db-athlete-2'),
    );

    await expect(prisma.athleteProfile.count({ where: { userId: actor.id } })).resolves.toBe(1);

    expect(created).toMatchObject({ city: 'Karachi', isMinor: false });
    expect(updated).toMatchObject({ city: 'Lahore', clubName: null, weightKg: null });
    expect(Date.parse(updated.updatedAt)).toBeGreaterThanOrEqual(Date.parse(created.updatedAt));
  });

  it('returns the stored row on a read after a save', async () => {
    const actor = await newAthlete();

    await service.saveProfile(actor, profile({ city: 'Oslo' }), ctx('db-athlete-3'));

    await expect(service.readProfile(actor, ctx('db-athlete-4'))).resolves.toMatchObject({
      city: 'Oslo',
      dateOfBirth: '2001-02-03',
      isMinor: false,
    });
  });

  it('never reaches another athlete profile', async () => {
    const owner = await newAthlete();
    const stranger = await newAthlete();

    await service.saveProfile(owner, profile({ city: 'Karachi' }), ctx('db-athlete-5'));

    // Nothing to read, and nothing the answer says about the other row.
    await refusalOf(service.readProfile(stranger, ctx('db-athlete-6')), NotFoundException);

    // Creating one's own row leaves the first account's row untouched.
    await service.saveProfile(stranger, profile({ legalFirstName: 'Grace' }), ctx('db-athlete-7'));

    await expect(prisma.athleteProfile.count({ where: { userId: owner.id } })).resolves.toBe(1);
    await expect(service.readProfile(owner, ctx('db-athlete-8'))).resolves.toMatchObject({
      legalFirstName: 'Ada',
      city: 'Karachi',
    });
    await expect(prisma.athleteProfile.count({ where: { userId: stranger.id } })).resolves.toBe(1);
  });

  it('audits the create and the update by field name, never by value', async () => {
    const actor = await newAthlete();

    await service.saveProfile(actor, profile(), ctx('db-athlete-9'));
    await service.saveProfile(actor, profile({ city: 'Lahore' }), ctx('db-athlete-10'));

    const trail = await prisma.auditLog.findMany({
      where: {
        targetId: actor.id,
        action: {
          in: [ATHLETE_AUDIT_ACTIONS.PROFILE_CREATE, ATHLETE_AUDIT_ACTIONS.PROFILE_UPDATE],
        },
      },
      select: { action: true, metadata: true, actorRole: true, targetType: true },
    });

    /** Order is the chain's business, not this test's: one row per action. */
    const rowFor = (action: string) => trail.filter((row) => row.action === action);

    expect(trail).toHaveLength(2);
    expect(rowFor(ATHLETE_AUDIT_ACTIONS.PROFILE_CREATE)).toHaveLength(1);
    expect(rowFor(ATHLETE_AUDIT_ACTIONS.PROFILE_UPDATE)).toHaveLength(1);

    for (const row of trail) {
      expect(row.actorRole).toBe(Role.ATHLETE);
      expect(row.targetType).toBe('athlete_profile');
    }

    // Every editable name on the first save; only what changed on the second.
    expect(rowFor(ATHLETE_AUDIT_ACTIONS.PROFILE_CREATE)[0]?.metadata).toEqual({
      fields: [
        'legalFirstName',
        'legalLastName',
        'dateOfBirth',
        'gender',
        'nationality',
        'countryOfResidence',
        'city',
        'clubName',
        'weightKg',
        'heightCm',
      ],
    });
    expect(rowFor(ATHLETE_AUDIT_ACTIONS.PROFILE_UPDATE)[0]?.metadata).toEqual({
      fields: ['city'],
    });

    // The trail names fields; it is not a copy of the profile.
    const text = JSON.stringify(trail);

    expect(text).not.toContain('Karachi');
    expect(text).not.toContain('Lahore');
    expect(text).not.toContain('2001-02-03');
    expect(text).not.toContain('KFA Academy');
  });
});
