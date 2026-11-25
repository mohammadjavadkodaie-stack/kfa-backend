import type { KnownCountryStore } from '../known-country-store';

/** Test double only: per-process state; production uses Redis for shared atomic state. */
export class InMemoryKnownCountryStore implements KnownCountryStore {
  private readonly countries = new Map<string, Set<string>>();

  async recordAndCheck(
    userId: string,
    country: string,
  ): Promise<{ isNew: boolean; hadAny: boolean }> {
    const known = this.countries.get(userId) ?? new Set<string>();
    const hadAny = known.size > 0;
    const isNew = !known.has(country);
    if (isNew && known.size < 20) known.add(country);
    this.countries.set(userId, known);
    return { isNew, hadAny };
  }
}
