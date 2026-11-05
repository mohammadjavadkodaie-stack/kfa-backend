import request from 'supertest';
import { createAdminHarness } from './admin-harness';
import { InMemoryAthleteProfileRepository } from './in-memory-athlete-profiles';

/**
 * The athlete profile surface over the real application: in-memory sessions and
 * an in-memory profile table, so the suites exercise the routes, the pipe, the
 * guards and the audit call without PostgreSQL.
 *
 * Accounts are created through the real register endpoint, exactly as the admin
 * suites do; only the profile store is swapped.
 */
export async function createAthleteHarness(prefix = 'athlete') {
  const profiles = new InMemoryAthleteProfileRepository();
  const base = await createAdminHarness(prefix, { athleteProfileRepository: profiles });
  const server = () => request(base.app.getHttpServer());

  const get = (path: string, token?: string) => {
    const call = server().get(path);

    return token === undefined ? call : call.set('Authorization', `Bearer ${token}`);
  };

  const put = (path: string, token?: string, body?: object) => {
    const call = server().put(path);

    if (token !== undefined) call.set('Authorization', `Bearer ${token}`);
    if (body !== undefined) call.send(body);

    return call;
  };

  return { ...base, profiles, get, put };
}

export type AthleteHarness = Awaited<ReturnType<typeof createAthleteHarness>>;
