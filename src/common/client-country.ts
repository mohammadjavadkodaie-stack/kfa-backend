import type { IncomingHttpHeaders } from 'node:http';

const COUNTRY_PATTERN = /^[A-Z]{2}$/u;

export function readClientCountry(headers: IncomingHttpHeaders, trusted: boolean): string | null {
  if (!trusted) return null;

  const header = headers['cf-ipcountry'];
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== 'string') return null;

  const country = value.trim().toUpperCase();
  if (country === 'XX' || !COUNTRY_PATTERN.test(country)) return null;

  return country;
}
