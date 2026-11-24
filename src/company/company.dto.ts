import { BadRequestException } from '@nestjs/common';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { z } from 'zod';

/**
 * The wire gate for the staff company profile routes.
 *
 * Every schema is a `strictObject`: a key it does not declare - `slug` on PATCH,
 * `deletedAt`, `createdById`, `id` - is the generic 400 instead of being
 * silently dropped. Text fields are plain text only: control characters and
 * angle brackets are refused, so no markup can be stored and later rendered by
 * a public page. The legal identity fields are accepted here because only staff
 * reach these routes; step 9b will select the public columns and nothing else.
 */

/** A page of companies, when the caller does not say how much it wants. */
export const DEFAULT_COMPANY_PAGE_SIZE = 20;

/** The hard cap on one page. */
export const MAX_COMPANY_PAGE_SIZE = 50;

export const COMPANY_KINDS = ['ORGANIZER', 'SPONSOR', 'PARTNER', 'OTHER'] as const;

export type CompanyKindValue = (typeof COMPANY_KINDS)[number];

export const MAX_DISPLAY_NAME_LENGTH = 120;
export const MAX_DESCRIPTION_LENGTH = 2_000;
export const MAX_WEBSITE_URL_LENGTH = 300;
export const MAX_LEGAL_NAME_LENGTH = 200;
export const MAX_ADDRESS_LENGTH = 500;
export const MAX_EMAIL_LENGTH = 254;

/** Control characters (including tab and newline) and the two tag brackets. */
const NOT_PLAIN_TEXT = /[\u0000-\u001f\u007f<>]/;

/** Trimmed, bounded and plain: a value of spaces is no value. */
function plainText(maxLength: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(maxLength)
    .refine((value) => !NOT_PLAIN_TEXT.test(value));
}

const slugSchema = z.string().regex(/^[a-z0-9-]{3,60}$/);

/** ISO 3166-1 alpha-2, uppercase, like `athlete_profiles.nationality`. */
const countrySchema = z.string().regex(/^[A-Z]{2}$/);

const kindSchema = z.enum(COMPANY_KINDS);

/** Digits only; the registry numbers are identifiers, never arithmetic. */
function digits(maxLength: number) {
  return z.string().regex(new RegExp(`^[0-9]{1,${maxLength}}$`));
}

const mersisSchema = z.string().regex(/^[0-9]{16}$/);

/** NACE as `12.34.56`; the dots are literal. */
const naceSchema = z.string().regex(/^[0-9]{2}\.[0-9]{2}\.[0-9]{2}$/);

const emailSchema = z
  .string()
  .trim()
  .max(MAX_EMAIL_LENGTH)
  .refine((value) => z.email().safeParse(value).success && !NOT_PLAIN_TEXT.test(value));

/** `YYYY-MM-DD`, and a real calendar day: 2026-02-30 is not one. */
export const chamberDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const parsed = new Date(`${value}T00:00:00.000Z`);

    return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
  })
  .transform((value) => new Date(`${value}T00:00:00.000Z`));

/**
 * https only, and never a host the server itself can reach: an IP literal, a
 * `localhost`/`*.local`/`*.internal` name, or a single-label intranet name.
 * A company website is a public link, so it must resolve on the public web.
 */
export function isPublicHttpsUrl(value: string): boolean {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') return false;

  const host = url.hostname.toLowerCase();

  // `[::1]` keeps its brackets, so a colon here is always an IPv6 literal.
  if (host === '' || host.includes(':')) return false;

  const localNames = ['localhost', '.localhost', '.local', '.internal'];

  if (localNames.some((name) => host === name || host.endsWith(name))) return false;

  // A public host always has a dot; a bare or all-numeric host is an internal
  // name, an IPv4 literal or an integer address.
  if (!host.includes('.') || /^[0-9.]+$/.test(host)) return false;

  return true;
}

const websiteUrlSchema = z
  .string()
  .trim()
  .max(MAX_WEBSITE_URL_LENGTH)
  .refine(isPublicHttpsUrl)
  .nullable()
  .optional();

const descriptionSchema = plainText(MAX_DESCRIPTION_LENGTH).nullable().optional();
const addressSchema = plainText(MAX_ADDRESS_LENGTH).nullable().optional();
const contactEmailSchema = emailSchema.nullable().optional();
const tradeRegistryNumberSchema = digits(20).nullable().optional();
const mersisNumberSchema = mersisSchema.nullable().optional();
const taxNumberSchema = digits(20).nullable().optional();
const taxOfficeSchema = plainText(120).nullable().optional();
const chamberNameSchema = plainText(200).nullable().optional();
const chamberRegisteredAtSchema = chamberDateSchema.nullable().optional();
const naceCodeSchema = naceSchema.nullable().optional();

/** `POST /staff/companies`. The slug is chosen once, here. */
export const createCompanySchema = z.strictObject({
  slug: slugSchema,
  displayName: plainText(MAX_DISPLAY_NAME_LENGTH),
  country: countrySchema,
  kind: kindSchema,
  description: descriptionSchema,
  websiteUrl: websiteUrlSchema,
  legalName: plainText(MAX_LEGAL_NAME_LENGTH),
  tradeRegistryNumber: tradeRegistryNumberSchema,
  mersisNumber: mersisNumberSchema,
  taxNumber: taxNumberSchema,
  taxOffice: taxOfficeSchema,
  chamberName: chamberNameSchema,
  chamberRegisteredAt: chamberRegisteredAtSchema,
  naceCode: naceCodeSchema,
  address: addressSchema,
  contactEmail: contactEmailSchema,
});

export type CreateCompanyWire = z.infer<typeof createCompanySchema>;

/** The wire gate: a body outside the schema is the generic 400. */
export function parseCreateCompany(body: unknown): CreateCompanyWire {
  const parsed = createCompanySchema.safeParse(body);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * `PATCH /staff/companies/:id`.
 *
 * `slug` is absent on purpose: it is the company's public identity and is fixed
 * at creation, so a body that carries it is the generic 400. An empty body is
 * not a patch either.
 */
export const updateCompanySchema = z
  .strictObject({
    displayName: plainText(MAX_DISPLAY_NAME_LENGTH).optional(),
    country: countrySchema.optional(),
    kind: kindSchema.optional(),
    description: descriptionSchema,
    websiteUrl: websiteUrlSchema,
    legalName: plainText(MAX_LEGAL_NAME_LENGTH).optional(),
    tradeRegistryNumber: tradeRegistryNumberSchema,
    mersisNumber: mersisNumberSchema,
    taxNumber: taxNumberSchema,
    taxOffice: taxOfficeSchema,
    chamberName: chamberNameSchema,
    chamberRegisteredAt: chamberRegisteredAtSchema,
    naceCode: naceCodeSchema,
    address: addressSchema,
    contactEmail: contactEmailSchema,
  })
  .refine((input) => Object.keys(input).length > 0);

export type UpdateCompanyWire = z.infer<typeof updateCompanySchema>;

export function parseUpdateCompany(body: unknown): UpdateCompanyWire {
  const parsed = updateCompanySchema.safeParse(body);

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}

/**
 * `GET /staff/companies?limit=&cursor=`.
 *
 * Every field is declared, so a misspelled or unknown parameter is the generic
 * 400 instead of being silently ignored.
 */
export class CompanyListQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_COMPANY_PAGE_SIZE)
  limit?: number;

  /** The `id` of the last company of the previous page. */
  @IsOptional()
  @IsUUID()
  cursor?: string;
}

/** The path parameter of the read, update and delete routes. */
export class CompanyParamsDto {
  @IsUUID()
  id!: string;
}
