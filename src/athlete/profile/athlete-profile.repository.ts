/**
 * Persistence boundary for the athlete profile.
 *
 * The profile belongs to a user, so every operation is keyed by `userId` and the
 * row id never leaves this layer. The API surface (controller, DTOs, own-profile
 * rules) is a later step; only the two primitives below exist today.
 */

/** DI token so the Prisma implementation can be swapped in tests. */
export const ATHLETE_PROFILE_REPOSITORY = Symbol('ATHLETE_PROFILE_REPOSITORY');

/**
 * Date-only string, `YYYY-MM-DD`. The column is DATE; handing a Date across the
 * boundary would let the process timezone move the birthday by a day.
 */
export type IsoDate = string;

export type Gender = 'FEMALE' | 'MALE' | 'OTHER' | 'UNDISCLOSED';

/** Everything the user may edit, minus the derived and audit columns. */
export interface AthleteProfileInput {
  readonly legalFirstName: string;
  readonly legalLastName: string;
  readonly dateOfBirth: IsoDate;
  readonly gender: Gender;
  /** ISO 3166-1 alpha-2, uppercase. */
  readonly nationality: string;
  /** ISO 3166-1 alpha-2, uppercase. */
  readonly countryOfResidence: string;
  readonly city: string;
  readonly clubName?: string | null;
  readonly weightKg?: number | null;
  readonly heightCm?: number | null;
}

/** One stored profile. `isMinor` is derived, so it is not part of the row. */
export interface AthleteProfileRecord extends Required<AthleteProfileInput> {
  readonly userId: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface AthleteProfileRepository {
  findByUserId(userId: string): Promise<AthleteProfileRecord | null>;
  /**
   * Inserts the profile or replaces it wholesale in one statement. The unique
   * `user_id` decides, so two concurrent first saves cannot both insert.
   */
  upsertForUser(userId: string, data: AthleteProfileInput): Promise<AthleteProfileRecord>;
}
