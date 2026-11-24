import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/**
 * `POST /photos/:photoId/report`.
 *
 * The body is two fields at most: a reason from a closed list and an optional
 * note. Nothing about the reporter, the owner or the photo travels in it - those
 * come from the token and the row. The note is flattened to one line and stripped
 * of control characters before it is stored; it is never rendered back to anyone,
 * and a note that is only whitespace is no note at all.
 */

/** Longest report note a caller may send, before cleaning. */
export const MAX_PHOTO_REPORT_NOTE_LENGTH = 200;

/** The closed list, kept in step with the `PhotoReportReason` enum. */
export const PHOTO_REPORT_REASONS = ['SPAM', 'ABUSE', 'NUDITY', 'OTHER'] as const;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/gu;
const WHITESPACE_RUN = /\s+/gu;

/** One line, no control characters, trimmed; `null` when nothing is left. */
export function sanitizeReportNote(raw: string): string | null {
  const collapsed = raw.replace(CONTROL_CHARACTERS, ' ').replace(WHITESPACE_RUN, ' ').trim();

  return collapsed.length === 0 ? null : collapsed;
}

export const photoReportSchema = z.strictObject({
  reason: z.enum(PHOTO_REPORT_REASONS),
  note: z
    .string()
    .max(MAX_PHOTO_REPORT_NOTE_LENGTH)
    .optional()
    .transform((value) => (value === undefined ? null : sanitizeReportNote(value))),
});

export type PhotoReportRequest = z.infer<typeof photoReportSchema>;

/**
 * The wire gate. A missing reason, an unknown reason, an unknown key or a note
 * that is too long is the generic 400 - never a list of what would have worked.
 */
export function parsePhotoReport(body: unknown): PhotoReportRequest {
  const parsed = photoReportSchema.safeParse(body ?? {});

  if (!parsed.success) throw new BadRequestException();

  return parsed.data;
}
