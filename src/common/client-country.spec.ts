import { readClientCountry } from './client-country';

describe('readClientCountry', () => {
  it.each([
    [false, { 'cf-ipcountry': 'TR' }, null],
    [true, {}, null],
    [true, { 'cf-ipcountry': [' tr '] }, 'TR'],
    [true, { 'cf-ipcountry': 'tr' }, 'TR'],
    [true, { 'cf-ipcountry': 'XX' }, null],
    [true, { 'cf-ipcountry': 'T1' }, null],
    [true, { 'cf-ipcountry': 'unknown' }, null],
    [true, { 'cf-ipcountry': 'USA' }, null],
    [true, { 'cf-ipcountry': 'TR' }, 'TR'],
  ])('returns %s for %o', (trusted, headers, expected) => {
    expect(readClientCountry(headers, trusted)).toBe(expected);
  });
});
