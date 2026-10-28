import { parsePhoneNumberFromString, type PhoneNumber } from 'libphonenumber-js/max';

const ACCEPTED_TYPES = new Set(['MOBILE', 'FIXED_LINE', 'FIXED_LINE_OR_MOBILE']);

export function normalizePhone(input: unknown): { e164: string } | null {
  if (typeof input !== 'string' || input.length > 256) return null;

  try {
    const phone = parsePhoneNumberFromString(input);
    if (
      !phone ||
      !phone.isPossible() ||
      !phone.isValid() ||
      !/^\+[1-9][0-9]{6,14}$/.test(phone.number)
    ) {
      return null;
    }
    const type = phone.getType();
    return type === undefined || ACCEPTED_TYPES.has(type) ? { e164: phone.number } : null;
  } catch {
    return null;
  }
}

export function maskPhone(e164: string): string {
  if (!/^\+[1-9][0-9]{6,14}$/.test(e164)) return '[INVALID_PHONE]';
  if (e164.length <= 5) return e164;
  return `${e164.slice(0, 3)}${'*'.repeat(Math.max(1, e164.length - 5))}${e164.slice(-2)}`;
}

export type NormalizedPhone = ReturnType<typeof normalizePhone>;
export type ParsedPhone = PhoneNumber;
