import { BadRequestException } from '@nestjs/common';
import {
  COMPANY_KINDS,
  createCompanySchema,
  isPublicHttpsUrl,
  MAX_DESCRIPTION_LENGTH,
  parseCreateCompany,
  parseUpdateCompany,
  updateCompanySchema,
} from './company.dto';

/**
 * The wire gate of the staff company routes.
 *
 * These cases pin the rules that are cheap to break later: a strict object (no
 * undeclared key), plain text only, https-only public URLs, the fixed number
 * formats, and the immutable slug.
 */

const VALID = {
  slug: 'bursa-atletizm-kulubu',
  displayName: 'Bursa Atletizm Kulübü',
  country: 'TR',
  kind: 'ORGANIZER',
  legalName: 'Bursa Atletizm Kulübü Derneği',
  description: 'Yerel yarışlar düzenler.',
  websiteUrl: 'https://ornek.org',
  tradeRegistryNumber: '123456',
  mersisNumber: '0123456789012345',
  taxNumber: '1234567890',
  taxOffice: 'Nilüfer',
  chamberName: 'Bursa Ticaret Odası',
  chamberRegisteredAt: '2019-04-01',
  naceCode: '93.12.01',
  address: 'Nilüfer, Bursa',
  contactEmail: 'info@ornek.org',
} as const;

describe('company DTO', () => {
  describe('create', () => {
    it('accepts a complete card and turns the chamber date into a Date', () => {
      const parsed = createCompanySchema.parse(VALID);

      expect(parsed.chamberRegisteredAt).toEqual(new Date('2019-04-01T00:00:00.000Z'));
      expect(parsed.kind).toBe('ORGANIZER');
    });

    it('accepts a minimal card: only the required fields', () => {
      const parsed = createCompanySchema.parse({
        slug: VALID.slug,
        displayName: VALID.displayName,
        country: VALID.country,
        kind: VALID.kind,
        legalName: VALID.legalName,
      });

      expect(parsed).toEqual({
        slug: VALID.slug,
        displayName: VALID.displayName,
        country: VALID.country,
        kind: VALID.kind,
        legalName: VALID.legalName,
      });
    });

    it('trims text and refuses a value that is only spaces', () => {
      expect(createCompanySchema.parse({ ...VALID, displayName: '  Kulüp  ' }).displayName).toBe(
        'Kulüp',
      );
      expect(createCompanySchema.safeParse({ ...VALID, displayName: '   ' }).success).toBe(false);
    });

    it('refuses a key it does not declare', () => {
      expect(createCompanySchema.safeParse({ ...VALID, createdById: 'x' }).success).toBe(false);
      expect(createCompanySchema.safeParse({ ...VALID, deletedAt: null }).success).toBe(false);
      expect(createCompanySchema.safeParse({ ...VALID, role: 'OWNER' }).success).toBe(false);
    });

    it.each([
      ['uppercase', 'Bursa'],
      ['too short', 'ab'],
      ['underscore', 'bursa_atletizm'],
      ['space', 'bursa atletizm'],
      ['61 characters', 'a'.repeat(61)],
    ])('refuses a %s slug', (_label, slug) => {
      expect(createCompanySchema.safeParse({ ...VALID, slug }).success).toBe(false);
    });

    it.each([
      ['lowercase country', { country: 'tr' }],
      ['three-letter country', { country: 'TUR' }],
      ['unknown kind', { kind: 'CLUB' }],
      ['mersis with 15 digits', { mersisNumber: '012345678901234' }],
      ['mersis with a letter', { mersisNumber: '012345678901234a' }],
      ['nace without the third pair', { naceCode: '93.12' }],
      ['nace with a dash', { naceCode: '93-12-01' }],
      ['tax number with a space', { taxNumber: '123 456' }],
      ['impossible chamber date', { chamberRegisteredAt: '2026-02-30' }],
      ['chamber date with slashes', { chamberRegisteredAt: '01/04/2019' }],
      ['malformed contact email', { contactEmail: 'info@' }],
    ])('refuses %s', (_label, override) => {
      expect(createCompanySchema.safeParse({ ...VALID, ...override }).success).toBe(false);
    });

    it.each([
      ['a script tag in the description', { description: '<script>alert(1)</script>' }],
      ['a newline in the display name', { displayName: 'Kulüp\nSahte' }],
      ['a NUL in the address', { address: 'Bursa\u0000' }],
      ['an over-long description', { description: 'x'.repeat(MAX_DESCRIPTION_LENGTH + 1) }],
    ])('refuses %s', (_label, override) => {
      expect(createCompanySchema.safeParse({ ...VALID, ...override }).success).toBe(false);
    });

    it.each([
      'http://ornek.org',
      'https://localhost',
      'https://app.localhost',
      'https://server.local',
      'https://intranet.internal',
      'https://intranet',
      'https://127.0.0.1',
      'https://10.0.0.5',
      'https://[::1]',
      'https://user:pass@ornek.org',
      'javascript:alert(1)',
      'https://2130706433',
    ])('refuses the website URL %s', (websiteUrl) => {
      expect(isPublicHttpsUrl(websiteUrl)).toBe(false);
      expect(createCompanySchema.safeParse({ ...VALID, websiteUrl }).success).toBe(false);
    });

    it.each(['https://ornek.org', 'https://www.ornek.org/uyeler?x=1', 'https://alt.ornek.co.uk'])(
      'accepts the public website URL %s',
      (websiteUrl) => {
        expect(isPublicHttpsUrl(websiteUrl)).toBe(true);
      },
    );

    it('accepts null for an optional field', () => {
      expect(createCompanySchema.parse({ ...VALID, websiteUrl: null }).websiteUrl).toBeNull();
    });

    it('answers the generic 400 through the parser', () => {
      expect(() => parseCreateCompany({ ...VALID, kind: 'CLUB' })).toThrow(BadRequestException);
      expect(() => parseCreateCompany(null)).toThrow(BadRequestException);
      expect(parseCreateCompany(VALID).slug).toBe(VALID.slug);
    });

    it('keeps the kind list closed', () => {
      expect(COMPANY_KINDS).toEqual(['ORGANIZER', 'SPONSOR', 'PARTNER', 'OTHER']);
    });
  });

  describe('update', () => {
    it('accepts a single field', () => {
      expect(updateCompanySchema.parse({ displayName: 'Yeni Ad' })).toEqual({
        displayName: 'Yeni Ad',
      });
    });

    it('accepts an explicit null to clear an optional field', () => {
      expect(updateCompanySchema.parse({ websiteUrl: null })).toEqual({ websiteUrl: null });
    });

    it('refuses the immutable slug: the company keeps its public identity', () => {
      expect(updateCompanySchema.safeParse({ slug: 'yeni-slug' }).success).toBe(false);
      expect(
        updateCompanySchema.safeParse({ slug: 'yeni-slug', taxOffice: 'Osmangazi' }).success,
      ).toBe(false);
    });

    it('refuses an empty body', () => {
      expect(updateCompanySchema.safeParse({}).success).toBe(false);
      expect(() => parseUpdateCompany({})).toThrow(BadRequestException);
    });

    it('refuses an undeclared key', () => {
      expect(updateCompanySchema.safeParse({ deletedAt: null }).success).toBe(false);
      expect(updateCompanySchema.safeParse({ id: VALID.slug }).success).toBe(false);
    });

    it('applies the same format rules as create', () => {
      expect(updateCompanySchema.safeParse({ mersisNumber: '123' }).success).toBe(false);
      expect(updateCompanySchema.safeParse({ websiteUrl: 'http://ornek.org' }).success).toBe(false);
      expect(updateCompanySchema.safeParse({ displayName: '<b>x</b>' }).success).toBe(false);
    });
  });
});
