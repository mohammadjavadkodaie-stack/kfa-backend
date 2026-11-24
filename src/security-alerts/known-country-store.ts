/** Stores the countries previously used to log in by user. */
export interface KnownCountryStore {
  recordAndCheck(userId: string, country: string): Promise<{ isNew: boolean; hadAny: boolean }>;
}

export const KNOWN_COUNTRY_STORE = Symbol('KNOWN_COUNTRY_STORE');
