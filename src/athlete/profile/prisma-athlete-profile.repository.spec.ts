import type { Prisma } from '@prisma/client';
import type { AthleteProfileInput } from './athlete-profile.repository';
import { PrismaAthleteProfileRepository } from './prisma-athlete-profile.repository';
import type { PrismaService } from '../../database/prisma.service';

interface UpsertArgs {
  where: { userId: string };
  create: Record<string, unknown>;
  update: Record<string, unknown>;
  select: Record<string, boolean>;
}

const storedRow = {
  userId: 'user-a',
  legalFirstName: 'Ada',
  legalLastName: 'Lovelace',
  dateOfBirth: new Date('2001-02-03T00:00:00.000Z'),
  gender: 'FEMALE',
  nationality: 'PK',
  countryOfResidence: 'SE',
  city: 'Karachi',
  clubName: null,
  weightKg: 61,
  heightCm: 168,
  createdAt: new Date('2026-11-08T10:00:00.000Z'),
  updatedAt: new Date('2026-11-08T10:00:00.000Z'),
};

const input: AthleteProfileInput = {
  legalFirstName: 'Ada',
  legalLastName: 'Lovelace',
  dateOfBirth: '2001-02-03',
  gender: 'FEMALE',
  nationality: 'PK',
  countryOfResidence: 'SE',
  city: 'Karachi',
  weightKg: 61,
  heightCm: 168,
};

/** Only the two methods the repository uses; everything else stays out of the fake. */
function createPrisma(found: typeof storedRow | null = storedRow) {
  return {
    athleteProfile: {
      upsert: jest.fn(async () => storedRow),
      findUnique: jest.fn(async () => found),
    },
  };
}

function upsertArgs(prisma: ReturnType<typeof createPrisma>): UpsertArgs | undefined {
  return (prisma.athleteProfile.upsert.mock.calls as unknown as UpsertArgs[][])[0]?.[0];
}

describe('PrismaAthleteProfileRepository', () => {
  it('writes with a single upsert keyed by the user id', async () => {
    const prisma = createPrisma();
    const repository = new PrismaAthleteProfileRepository(prisma as unknown as PrismaService);

    await repository.upsertForUser('user-a', input);

    expect(prisma.athleteProfile.upsert).toHaveBeenCalledTimes(1);
    expect(upsertArgs(prisma)?.where).toEqual({ userId: 'user-a' });
    expect(upsertArgs(prisma)?.create).toMatchObject({ userId: 'user-a', city: 'Karachi' });
    // The user id is the predicate, never a column the replace branch may rewrite.
    expect(upsertArgs(prisma)?.update).not.toHaveProperty('userId');
  });

  it('runs the upsert on the transaction it is given', async () => {
    const prisma = createPrisma();
    const tx = { athleteProfile: { upsert: jest.fn(async () => storedRow) } };
    const repository = new PrismaAthleteProfileRepository(prisma as unknown as PrismaService);

    const record = await repository.upsertForUser(
      'user-a',
      input,
      tx as unknown as Prisma.TransactionClient,
    );

    // The caller's transaction owns the write; the pool client is not touched.
    expect(tx.athleteProfile.upsert).toHaveBeenCalledTimes(1);
    expect(prisma.athleteProfile.upsert).not.toHaveBeenCalled();
    expect(record).toMatchObject({ userId: 'user-a', dateOfBirth: '2001-02-03' });
  });

  it('stores the birth date at UTC midnight and reads it back date-only', async () => {
    const prisma = createPrisma();
    const repository = new PrismaAthleteProfileRepository(prisma as unknown as PrismaService);

    const record = await repository.upsertForUser('user-a', input);

    expect(upsertArgs(prisma)?.create.dateOfBirth).toEqual(new Date('2001-02-03T00:00:00.000Z'));
    expect(record.dateOfBirth).toBe('2001-02-03');
    expect(record.userId).toBe('user-a');
  });

  it('returns null for a user without a profile', async () => {
    const prisma = createPrisma(null);
    const repository = new PrismaAthleteProfileRepository(prisma as unknown as PrismaService);

    await expect(repository.findByUserId('user-b')).resolves.toBeNull();
    expect(prisma.athleteProfile.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'user-b' } }),
    );
  });
});
