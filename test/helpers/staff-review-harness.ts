import request from 'supertest';
import type { AthleteProfileRecord } from '../../src/athlete/profile/athlete-profile.repository';
import { FakeEmailProvider } from '../../src/auth/email/email.provider';
import { Role } from '../../src/auth/roles';
import { createAdminHarness, type AdminAccount } from './admin-harness';
import { InMemoryAthleteProfileRepository } from './in-memory-athlete-profiles';
import { InMemoryStaffReviews } from './in-memory-staff-reviews';

/**
 * The review surface over the real application: in-memory sessions, an in-memory
 * profile table, an in-memory document table and the recording email fake, so
 * every suite exercises the routes, the guards, the pipe, the audit chain and the
 * decision email without PostgreSQL, Redis or a bucket.
 *
 * Athletes are created through the real register, save and submit endpoints.
 * That is the whole point of this fixture: a PENDING row is produced the way a
 * real one is, not written straight into the store.
 */

/** The same calendar day, `years` years back, so a fixed clock is not needed. */
function yearsAgo(years: number): string {
  const now = new Date();

  return new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()))
    .toISOString()
    .slice(0, 10);
}

/** A body the profile pipe accepts: a ten-year-old athlete, so a minor. */
export function profileBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    legalFirstName: 'Ada',
    legalLastName: 'Lovelace',
    dateOfBirth: yearsAgo(10),
    gender: 'FEMALE',
    nationality: 'PK',
    countryOfResidence: 'SE',
    city: 'Karachi',
    clubName: 'KFA Academy',
    weightKg: 41,
    heightCm: 152,
    ...overrides,
  };
}

/** A stored row, built from the same valid values the routes accept. */
function profileRecord(
  userId: string,
  overrides: Partial<AthleteProfileRecord> = {},
): AthleteProfileRecord {
  const now = new Date();

  return {
    userId,
    legalFirstName: 'Ada',
    legalLastName: 'Lovelace',
    dateOfBirth: yearsAgo(10),
    gender: 'FEMALE',
    nationality: 'PK',
    countryOfResidence: 'SE',
    city: 'Karachi',
    clubName: 'KFA Academy',
    weightKg: 41,
    heightCm: 152,
    createdAt: now,
    updatedAt: now,
    reviewStatus: 'PENDING',
    submittedAt: now,
    reviewedAt: null,
    reviewedById: null,
    rejectionReason: null,
    ...overrides,
  };
}

export async function createStaffReviewHarness(prefix = 'review') {
  const profiles = new InMemoryAthleteProfileRepository();
  const reviews = new InMemoryStaffReviews();
  const email = new FakeEmailProvider();
  const base = await createAdminHarness(prefix, {
    athleteProfileRepository: profiles,
    staffReviewRepository: reviews,
    emailProvider: email,
  });

  const server = () => request(base.app.getHttpServer());

  /** A read with no token at all: the only way to see the 401 envelope. */
  const anon = (path: string) => server().get(path);

  const put = (path: string, token?: string, body?: object) => {
    const call = server().put(path);

    if (token !== undefined) call.set('Authorization', `Bearer ${token}`);
    if (body !== undefined) call.send(body);

    return call;
  };

  /** The submit precondition and the queue count read different stores; fill both. */
  function grantDocument(userId: string): void {
    base.documents.set(userId, 1);
    reviews.addDocument(userId);
  }

  /**
   * A new ATHLETE account whose profile is PENDING, produced by the real save
   * and submit routes. `grantDocument` runs first because submit refuses a
   * profile with no identity document.
   */
  async function submittedAthlete(overrides: Record<string, unknown> = {}): Promise<{
    account: AdminAccount;
    profile: AthleteProfileRecord;
  }> {
    const account = await base.signUp(Role.ATHLETE);

    base.sessions.seedAthleteProfile(account.userId);
    grantDocument(account.userId);

    const saved = await put('/athlete/profile', account.token, profileBody(overrides));

    if (saved.status !== 200) throw new Error(`the profile of ${account.userId} was not saved`);

    const submitted = await base.post(
      '/athlete/profile/submit',
      account.token,
      profileBody(overrides),
    );

    if (submitted.status !== 200) {
      throw new Error(`the profile of ${account.userId} was not submitted`);
    }

    const profile = profiles.rows.get(account.userId);

    if (profile === undefined) throw new Error(`the profile of ${account.userId} is missing`);

    return { account, profile };
  }

  /** Writes a row straight into the store: the deterministic way to fix an order. */
  function seedProfile(
    userId: string,
    overrides: Partial<AthleteProfileRecord> = {},
  ): AthleteProfileRecord {
    const record = profileRecord(userId, overrides);

    profiles.rows.set(userId, record);

    return record;
  }

  /**
   * A staff account that passed the gate `minutesAgo` minutes ago. The default
   * keeps the five-minute step-up window open; a larger value closes it.
   */
  async function staff(
    role: Role = Role.ADMIN,
    minutesAgo = 0,
  ): Promise<AdminAccount & { sessionId: string }> {
    const account = await base.signUp(role, true);

    if (minutesAgo > 0) {
      const session = base.sessions.sessions.get(account.sessionId);

      if (session === undefined) throw new Error('the staff session is missing');

      session.stepupAt = new Date(Date.now() - minutesAgo * 60_000);
    }

    return account;
  }

  return {
    ...base,
    profiles,
    reviews,
    email,
    anon,
    put,
    grantDocument,
    submittedAthlete,
    seedProfile,
    staff,
  };
}

export type StaffReviewHarness = Awaited<ReturnType<typeof createStaffReviewHarness>>;
