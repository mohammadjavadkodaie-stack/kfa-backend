import { METHOD_METADATA } from '@nestjs/common/constants';
import { AthleteController } from '../src/athlete/athlete.controller';
import { AUTHENTICATED_KEY } from '../src/auth/decorators/authenticated.decorator';
import { Role } from '../src/auth/roles';
import { IS_PUBLIC_KEY } from '../src/common/decorators/public.decorator';
import { createAthleteHarness, type AthleteHarness } from './helpers/athlete-harness';
import type { AdminAccount } from './helpers/admin-harness';

/**
 * Stage 4.1c: the athlete profile routes over the real application.
 *
 * The store is in-memory, the pipe, the guards and the audit call are the real
 * ones, so what is proved here is the contract: no route without a token, no
 * route that takes a user id, a strict body, and a generic failure that repeats
 * none of the submitted values.
 */

const UNAUTHORIZED = { statusCode: 401, message: 'Unauthorized' } as const;
const BAD_REQUEST = { statusCode: 400, message: 'Bad Request' } as const;
const NOT_FOUND = { statusCode: 404, message: 'Not Found' } as const;

/** The same calendar day, `years` years back, so a fixed clock is not needed. */
function yearsAgo(years: number): string {
  const now = new Date();

  return new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()))
    .toISOString()
    .slice(0, 10);
}

function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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

/** The fields the API promises, and nothing else. */
const VIEW_FIELDS = [
  'city',
  'clubName',
  'countryOfResidence',
  'dateOfBirth',
  'gender',
  'heightCm',
  'isMinor',
  'legalFirstName',
  'legalLastName',
  'nationality',
  'updatedAt',
  'weightKg',
];

describe('Athlete profile routes (e2e)', () => {
  let harness: AthleteHarness;
  let athlete: AdminAccount;
  let other: AdminAccount;

  beforeAll(async () => {
    harness = await createAthleteHarness('athlete_profile');
    athlete = await harness.signUp(Role.ATHLETE);
    other = await harness.signUp(Role.ATHLETE);
  });

  afterAll(async () => {
    await harness.close();
  });

  it('refuses both routes without a token, and writes nothing', async () => {
    const read = await harness.get('/athlete/profile');
    const write = await harness.put('/athlete/profile', undefined, body());

    expect(read.status).toBe(401);
    expect(read.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    expect(write.status).toBe(401);
    expect(write.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    expect(harness.profiles.writes).toEqual([]);
  });

  it('saves the caller profile and reads the same row back', async () => {
    const saved = await harness.put('/athlete/profile', athlete.token, body());

    expect(saved.status).toBe(200);
    expect(Object.keys(saved.body as object).sort()).toEqual(VIEW_FIELDS);
    expect(saved.body).toMatchObject({ ...body(), isMinor: true });

    const read = await harness.get('/athlete/profile', athlete.token);

    expect(read.status).toBe(200);
    expect(read.body).toEqual(saved.body);
    expect(harness.profiles.rows.size).toBe(1);
  });

  it('rejects a body that names a user or a role, and keeps the stored row', async () => {
    const before = harness.profiles.writes.length;

    for (const extra of [{ role: 'ADMIN' }, { userId: other.userId }]) {
      const response = await harness.put('/athlete/profile', athlete.token, body(extra));

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
      // The generic envelope repeats neither the key nor its value.
      expect(JSON.stringify(response.body)).not.toMatch(/role|userId|ADMIN/i);
      expect(JSON.stringify(response.body)).not.toContain(other.userId);
    }

    expect(harness.profiles.writes).toHaveLength(before);
    expect(harness.profiles.rows.size).toBe(1);
  });

  it('rejects an impossible date and an unknown country without changing the row', async () => {
    const stored = await harness.get('/athlete/profile', athlete.token);

    for (const bad of [{ dateOfBirth: '2001-02-30' }, { nationality: 'ZZ' }, { weightKg: 500 }]) {
      const response = await harness.put('/athlete/profile', athlete.token, body(bad));

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    }

    const after = await harness.get('/athlete/profile', athlete.token);

    expect(after.body).toEqual(stored.body);
  });

  it('ignores a user id in the query and has no id in the path', async () => {
    const withQuery = await harness.get(`/athlete/profile?userId=${other.userId}`, athlete.token);

    // The query is not part of the contract, so the answer stays the caller's row.
    expect(withQuery.status).toBe(200);
    expect(withQuery.body).toMatchObject({ city: 'Karachi' });

    const withPath = await harness.put(`/athlete/profile/${other.userId}`, athlete.token, body());

    expect(withPath.status).toBe(404);
    expect(withPath.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    expect(harness.profiles.rows.has(other.userId)).toBe(false);
  });

  it('keeps one row and audits every save by field name only', async () => {
    const reader = await harness.signUp(Role.USER);

    const first = await harness.put('/athlete/profile', reader.token, body());
    const second = await harness.put(
      '/athlete/profile',
      reader.token,
      body({ city: 'Lahore', weightKg: null }),
    );

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    const readBack = await harness.get('/athlete/profile', reader.token);

    expect(readBack.body).toMatchObject({ city: 'Lahore', weightKg: null });

    // One row per caller, whatever the number of saves.
    const rowsOfCaller = [...harness.profiles.rows.values()].filter(
      (row) => row.userId === reader.userId,
    );

    expect(rowsOfCaller).toHaveLength(1);

    const creates = harness.rows('athlete.profile.create', reader.userId);
    const updates = harness.rows('athlete.profile.update', reader.userId);

    expect(creates).toHaveLength(1);
    expect(updates).toHaveLength(1);
    expect(creates[0]?.metadata).toEqual({ fields: expect.any(Array) });
    expect(updates[0]?.metadata).toEqual({ fields: ['city', 'weightKg'] });

    const trail = JSON.stringify([...creates, ...updates]);

    expect(trail).not.toContain('Karachi');
    expect(trail).not.toContain('Lahore');
    expect(trail).not.toContain(yearsAgo(10));
  });

  it('marks both handlers as authenticated and never public', () => {
    const prototype = AthleteController.prototype as unknown as Record<string, unknown>;
    const handlers = Object.getOwnPropertyNames(prototype).filter((name) => {
      const handler = prototype[name];

      return (
        typeof handler === 'function' && Reflect.getMetadata(METHOD_METADATA, handler) !== undefined
      );
    });

    expect(handlers.sort()).toEqual(['read', 'save']);

    for (const name of handlers) {
      const handler = prototype[name] as object;

      expect(Reflect.getMetadata(AUTHENTICATED_KEY, handler)).toBe(true);
      expect(Reflect.getMetadata(IS_PUBLIC_KEY, handler)).toBeUndefined();
    }
  });
});
