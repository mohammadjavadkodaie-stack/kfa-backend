/**
 * Age rules for the athlete profile.
 *
 * A birthday is a calendar day, not an instant, so everything here reads
 * `YYYY-MM-DD` and the UTC calendar: a server timezone must not be able to make
 * somebody an adult a day early or a day late.
 */

export type Clock = () => Date;

/** The one place the current instant enters the profile rules, so tests can fix it. */
export const CLOCK = Symbol('KFA_CLOCK');

export const SYSTEM_CLOCK: Clock = () => new Date();

/** The 18th birthday is an adult day: `isMinor` is already false on it. */
export const ADULT_AGE_YEARS = 18;

/** Sanity window for a stored profile; outside it the request is refused. */
export const MIN_AGE_YEARS = 5;
export const MAX_AGE_YEARS = 100;

export interface CalendarDay {
  readonly year: number;
  readonly month: number;
  readonly day: number;
}

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * Strict parse: a day that does not exist (`2001-02-30`) is refused instead of
 * rolling over into March, which is what `new Date()` would do.
 */
export function parseBirthDate(value: unknown): CalendarDay | null {
  if (typeof value !== 'string') return null;

  const match = ISO_DAY.exec(value);

  if (match === null) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const utc = new Date(Date.UTC(year, month - 1, day));

  if (
    utc.getUTCFullYear() !== year ||
    utc.getUTCMonth() !== month - 1 ||
    utc.getUTCDate() !== day
  ) {
    return null;
  }

  return { year, month, day };
}

/** Whole years elapsed on the calendar, so the birthday itself already counts. */
export function ageInYears(birth: CalendarDay, now: Date): number {
  const month = now.getUTCMonth() + 1;
  const day = now.getUTCDate();
  const hadBirthday = month > birth.month || (month === birth.month && day >= birth.day);

  return now.getUTCFullYear() - birth.year - (hadBirthday ? 0 : 1);
}

/**
 * Derived, never stored. An unreadable day stays a minor: the safe answer is
 * the one that still asks for a guardian.
 */
export function isMinor(dateOfBirth: string, now: Date): boolean {
  const birth = parseBirthDate(dateOfBirth);

  return birth === null || ageInYears(birth, now) < ADULT_AGE_YEARS;
}
