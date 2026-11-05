import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../database/prisma.service';
import type {
  AthleteProfileInput,
  AthleteProfileRecord,
  AthleteProfileRepository,
} from './athlete-profile.repository';

/** Columns the repository reads back; the row id and the user relation stay inside. */
const RECORD_FIELDS = {
  userId: true,
  legalFirstName: true,
  legalLastName: true,
  dateOfBirth: true,
  gender: true,
  nationality: true,
  countryOfResidence: true,
  city: true,
  clubName: true,
  weightKg: true,
  heightCm: true,
  createdAt: true,
  updatedAt: true,
} as const;

type ProfileRow = Prisma.AthleteProfileGetPayload<{ select: typeof RECORD_FIELDS }>;

/** DATE column: anchor the day at UTC midnight so no server timezone shifts it. */
function toStoredDate(isoDate: string): Date {
  return new Date(`${isoDate}T00:00:00.000Z`);
}

/** The user id never moves once the row exists, so the update branch must not carry it. */
function toColumns(data: AthleteProfileInput) {
  return {
    legalFirstName: data.legalFirstName,
    legalLastName: data.legalLastName,
    dateOfBirth: toStoredDate(data.dateOfBirth),
    gender: data.gender,
    nationality: data.nationality,
    countryOfResidence: data.countryOfResidence,
    city: data.city,
    clubName: data.clubName ?? null,
    weightKg: data.weightKg ?? null,
    heightCm: data.heightCm ?? null,
  };
}

function toRecord(row: ProfileRow): AthleteProfileRecord {
  // Stored at midnight UTC, so the first ten characters are exactly the day.
  return { ...row, dateOfBirth: row.dateOfBirth.toISOString().slice(0, 10) };
}

@Injectable()
export class PrismaAthleteProfileRepository implements AthleteProfileRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findByUserId(userId: string): Promise<AthleteProfileRecord | null> {
    const row = await this.prisma.athleteProfile.findUnique({
      where: { userId },
      select: RECORD_FIELDS,
    });

    return row === null ? null : toRecord(row);
  }

  /** One statement: the unique `user_id` resolves insert versus replace atomically. */
  async upsertForUser(userId: string, data: AthleteProfileInput): Promise<AthleteProfileRecord> {
    const row = await this.prisma.athleteProfile.upsert({
      where: { userId },
      create: { userId, ...toColumns(data) },
      update: toColumns(data),
      select: RECORD_FIELDS,
    });

    return toRecord(row);
  }
}
