import { ValidationPipe } from '@nestjs/common';
import { AthleteProfileDto } from './athlete-profile.dto';

/** Same options as `configureApp`, so the spec tests the pipe production runs. */
const pipe = new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true });

const metadata = { type: 'body' as const, metatype: AthleteProfileDto };

function valid(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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

function accepted(body: Record<string, unknown> = valid()): Promise<AthleteProfileDto> {
  return pipe.transform(body, metadata) as Promise<AthleteProfileDto>;
}

async function rejected(body: Record<string, unknown> = valid()): Promise<void> {
  await expect(pipe.transform(body, metadata)).rejects.toThrow();
}

/** The same calendar day, `years` years back, so a fixed clock is not needed. */
function yearsAgo(years: number): string {
  const now = new Date();
  const day = new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()));

  return day.toISOString().slice(0, 10);
}

describe('AthleteProfileDto', () => {
  it('accepts a complete body and trims the names', async () => {
    const dto = await accepted(valid({ legalFirstName: '  Ada  ', city: ' Karachi ' }));

    expect(dto).toBeInstanceOf(AthleteProfileDto);
    expect(dto).toMatchObject({ legalFirstName: 'Ada', city: 'Karachi' });
  });

  it('accepts a body without the optional measurements', async () => {
    const dto = await accepted({
      legalFirstName: 'Ada',
      legalLastName: 'Lovelace',
      dateOfBirth: yearsAgo(20),
      gender: 'UNDISCLOSED',
      nationality: 'PK',
      countryOfResidence: 'SE',
      city: 'Karachi',
    });

    expect(dto.clubName).toBeUndefined();
    expect(dto.weightKg).toBeUndefined();
    expect(dto.heightCm).toBeUndefined();
  });

  it('accepts the edges of the measurement ranges', async () => {
    await expect(accepted(valid({ weightKg: 20, heightCm: 100 }))).resolves.toBeDefined();
    await expect(accepted(valid({ weightKg: 300, heightCm: 250 }))).resolves.toBeDefined();
  });

  it('refuses a day the calendar does not have', async () => {
    await rejected(valid({ dateOfBirth: '2001-02-30' }));
  });

  it('refuses a birth date in the future', async () => {
    await rejected(valid({ dateOfBirth: '2999-01-01' }));
  });

  it('refuses an age under five', async () => {
    await rejected(valid({ dateOfBirth: yearsAgo(4) }));
  });

  it('refuses an age over a hundred', async () => {
    await rejected(valid({ dateOfBirth: yearsAgo(101) }));
  });

  it('refuses a country code outside the fixed list', async () => {
    await rejected(valid({ nationality: 'ZZ' }));
    await rejected(valid({ countryOfResidence: 'pk' }));
  });

  it('refuses an unknown gender', async () => {
    await rejected(valid({ gender: 'UNKNOWN' }));
  });

  it('refuses a field the contract does not declare', async () => {
    await rejected(valid({ role: 'ADMIN' }));
    await rejected(valid({ userId: '11111111-1111-4111-8111-111111111111' }));
  });

  it('refuses a missing required field', async () => {
    const body = valid();
    delete body.city;

    await rejected(body);
  });

  it('refuses a name that is only whitespace', async () => {
    await rejected(valid({ legalFirstName: '   ' }));
    await rejected(valid({ legalLastName: '' }));
  });

  it('refuses an over-long name', async () => {
    await rejected(valid({ legalFirstName: 'a'.repeat(101) }));
  });

  it('refuses a measurement outside the stored range', async () => {
    await rejected(valid({ weightKg: 19 }));
    await rejected(valid({ weightKg: 301 }));
    await rejected(valid({ heightCm: 99 }));
    await rejected(valid({ heightCm: 251 }));
  });

  it('refuses a measurement that is not a whole number', async () => {
    await rejected(valid({ weightKg: '61' }));
    await rejected(valid({ heightCm: 168.5 }));
  });
});
