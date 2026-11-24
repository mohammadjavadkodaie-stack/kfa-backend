import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/**
 * Caption rules for a profile photo.
 *
 * The caption is plain text and entirely optional. It is validated with zod -
 * the strict object refuses an unknown query key, so a misspelled parameter is a
 * 400 instead of a silently ignored one - and then sanitized on the server: a
 * single line, no control characters and no markup. The escaped form is what the
 * database holds, so no stored caption can carry a tag into a page.
 */

/** Longest caption a caller may send, before escaping. */
export const MAX_PHOTO_CAPTION_LENGTH = 200;

/**
 * Worst case after escaping: every character becomes a six-character entity,
 * which is exactly what the `varchar(1000)` column holds.
 */
export const MAX_STORED_CAPTION_LENGTH = MAX_PHOTO_CAPTION_LENGTH * 5;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/gu;
const WHITESPACE_RUN = /\s+/gu;
const HTML_ESCAPES: Readonly<Record<string, string>> = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&#34;',
  "'": '&#39;',
});

/** Removes control characters, flattens whitespace and escapes HTML metacharacters. */
export function sanitizeCaption(raw: string): string | null {
  const collapsed = raw.replace(CONTROL_CHARACTERS, ' ').replace(WHITESPACE_RUN, ' ').trim();

  if (collapsed.length === 0) return null;

  return collapsed.replace(/[&<>"']/gu, (character) => HTML_ESCAPES[character] ?? character);
}

/** The raw input gate: length is checked before escaping, so 200 `&` still fits. */
export const photoCaptionSchema = z
  .string()
  .max(MAX_PHOTO_CAPTION_LENGTH)
  .optional()
  .transform((value) => (value === undefined ? null : sanitizeCaption(value)));

/**
 * `POST /athlete/profile/photos?caption=...`.
 *
 * Only the caption travels in the query; the photo itself is the raw body and
 * every other fact (owner, status, object key) is decided by the server.
 */
export const photoUploadQuerySchema = z.strictObject({
  caption: photoCaptionSchema,
});

export type PhotoUploadQuery = z.infer<typeof photoUploadQuerySchema>;

/** The wire gate: a query outside the schema is the generic 400. */
export function parsePhotoUploadQuery(query: unknown): PhotoUploadQuery {
  const result = photoUploadQuerySchema.safeParse(query);

  if (!result.success) throw new BadRequestException();

  return result.data;
}

/** The path parameter, checked here because the upload route's query is not a DTO. */
export const photoIdSchema = z.uuid();

/** A foreign or missing id never reaches storage: both are answered by the service. */
export function parsePhotoId(value: unknown): string {
  const result = photoIdSchema.safeParse(value);

  if (!result.success) throw new BadRequestException();

  return result.data;
}
