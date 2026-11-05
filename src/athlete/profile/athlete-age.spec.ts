import { ageInYears, isMinor, parseBirthDate } from './athlete-age';

/** A fixed clock: noon UTC, so no test can drift across midnight. */
const at = (isoDay: string): Date => new Date(`${isoDay}T12:00:00.000Z`);

describe('isMinor', () => {
  it('is a minor the day before the 18th birthday', () => {
    expect(isMinor('2008-06-15', at('2026-06-14'))).toBe(true);
  });

  it('is an adult on the 18th birthday', () => {
    expect(isMinor('2008-06-15', at('2026-06-15'))).toBe(false);
  });

  it('stays an adult the day after', () => {
    expect(isMinor('2008-06-15', at('2026-06-16'))).toBe(false);
  });

  it('turns on the leap-day birthday without rolling into March', () => {
    expect(isMinor('2008-02-29', at('2026-02-27'))).toBe(true);
    expect(isMinor('2008-02-29', at('2026-02-28'))).toBe(true);
    expect(isMinor('2008-02-29', at('2026-03-01'))).toBe(false);
  });

  it('stays a minor when the day cannot be read', () => {
    expect(isMinor('2001-02-30', at('2026-06-15'))).toBe(true);
  });
});

describe('ageInYears', () => {
  it('counts the birthday itself as a full year', () => {
    const birth = parseBirthDate('2000-03-01');

    if (birth === null) throw new Error('the fixture date must parse');

    expect(ageInYears(birth, at('2025-02-28'))).toBe(24);
    expect(ageInYears(birth, at('2025-03-01'))).toBe(25);
  });
});

describe('parseBirthDate', () => {
  it('refuses a day the calendar does not have', () => {
    expect(parseBirthDate('2001-02-30')).toBeNull();
    expect(parseBirthDate('2023-13-01')).toBeNull();
  });

  it('refuses anything that is not a plain day', () => {
    expect(parseBirthDate('2001-2-3')).toBeNull();
    expect(parseBirthDate('2001-02-03T00:00:00Z')).toBeNull();
    expect(parseBirthDate(20010203)).toBeNull();
  });

  it('reads a real day', () => {
    expect(parseBirthDate('2001-02-28')).toEqual({ year: 2001, month: 2, day: 28 });
  });
});
