import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { AthleteProfileInput } from '../../src/athlete/profile/athlete-profile.repository';
import { PrismaAthleteProfileRepository } from '../../src/athlete/profile/prisma-athlete-profile.repository';
import type { PrismaService } from '../../src/database/prisma.service';
import { createTestPrisma, describeWithDatabase } from './helpers/database';

/**
 * Stage 4.1a: the athlete profile table against a real PostgreSQL, as `kfa_app`.
 * The CHECK constraints, the single-row-per-user rule and the withheld DELETE
 * are the guarantees the future API will lean on.
 */

const unique = (prefix: string) => `${prefix}_${randomUUID().replaceAll('-', '')}`.slice(0, 30);

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '4')
    .slice(0, 7)}`;
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

describeWithDatabase('athlete profile persistence (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let repository: PrismaAthleteProfileRepository;
  const userIds: string[] = [];

  /** ADMIN, not OWNER: the row trigger only fences the single owner account. */
  const newUser = async (): Promise<string> => {
    const user = await prisma.user.create({
      data: { phone: phone(), username: unique('athlete'), role: 'ADMIN' },
    });

    userIds.push(user.id);

    return user.id;
  };

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    repository = new PrismaAthleteProfileRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    // A profile row only goes away with its account (ON DELETE CASCADE).
    if (prisma) {
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
      await prisma.$disconnect();
    }
  });

  it('keeps one row when the same user saves twice', async () => {
    const userId = await newUser();

    await repository.upsertForUser(userId, profile());
    const second = await repository.upsertForUser(
      userId,
      profile({ city: 'Lahore', clubName: null, weightKg: null }),
    );

    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(1);
    expect(second).toMatchObject({
      city: 'Lahore',
      clubName: null,
      weightKg: null,
      dateOfBirth: '2001-02-03',
    });
    await expect(repository.findByUserId(userId)).resolves.toMatchObject({ city: 'Lahore' });
  });

  it('rejects a birth date in the future', async () => {
    const userId = await newUser();
    const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await expect(
      prisma.athleteProfile.create({ data: { userId, ...profile(), dateOfBirth: tomorrow } }),
    ).rejects.toThrow();

    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(0);
  });

  it('rejects a weight or height outside the allowed range', async () => {
    const userId = await newUser();

    for (const bad of [{ weightKg: -1 }, { weightKg: 400 }, { heightCm: 20 }, { heightCm: 300 }]) {
      await expect(
        prisma.athleteProfile.create({ data: { userId, ...profile(bad) } }),
      ).rejects.toThrow();
    }

    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(0);
  });

  it('rejects a country code that is not uppercase alpha-2', async () => {
    const userId = await newUser();

    for (const bad of [{ nationality: 'pk' }, { countryOfResidence: 'P1' }, { nationality: '' }]) {
      await expect(
        prisma.athleteProfile.create({ data: { userId, ...profile(bad) } }),
      ).rejects.toThrow();
    }

    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(0);
  });

  it('rejects an empty name, an empty city and an over-long city', async () => {
    const userId = await newUser();

    for (const bad of [
      { legalFirstName: '' },
      { legalLastName: '   ' },
      { city: '' },
      { city: 'k'.repeat(101) },
    ]) {
      await expect(
        prisma.athleteProfile.create({ data: { userId, ...profile(bad) } }),
      ).rejects.toThrow();
    }

    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(0);
  });

  it('does not let the runtime role delete a profile', async () => {
    const userId = await newUser();
    await repository.upsertForUser(userId, profile());

    const [privileges] = await prisma.$queryRaw<
      Array<{
        can_select: boolean;
        can_insert: boolean;
        can_update: boolean;
        can_delete: boolean;
      }>
    >`
      SELECT
        has_table_privilege(current_user, 'public.athlete_profiles', 'SELECT') AS can_select,
        has_table_privilege(current_user, 'public.athlete_profiles', 'INSERT') AS can_insert,
        has_table_privilege(current_user, 'public.athlete_profiles', 'UPDATE') AS can_update,
        has_table_privilege(current_user, 'public.athlete_profiles', 'DELETE') AS can_delete
    `;

    expect(privileges).toEqual({
      can_select: true,
      can_insert: true,
      can_update: true,
      can_delete: false,
    });

    await expect(prisma.athleteProfile.delete({ where: { userId } })).rejects.toThrow(
      /permission denied/i,
    );
    await expect(prisma.athleteProfile.count({ where: { userId } })).resolves.toBe(1);
  });

  it('never returns another user profile', async () => {
    const userA = await newUser();
    const userB = await newUser();

    await repository.upsertForUser(userA, profile());

    await expect(repository.findByUserId(userB)).resolves.toBeNull();

    await repository.upsertForUser(userB, profile({ legalFirstName: 'Grace', city: 'Oslo' }));

    await expect(repository.findByUserId(userA)).resolves.toMatchObject({
      legalFirstName: 'Ada',
      city: 'Karachi',
    });
  });
});
