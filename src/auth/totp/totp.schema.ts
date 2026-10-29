import { z } from 'zod';

/**
 * Bodies of the second-factor endpoints.
 *
 * `strictObject` keeps the whitelist explicit: the user is always taken from
 * the verified token, so a `userId` field would only be a spoofing attempt.
 */

/** A 6-digit TOTP code or a recovery code; anything longer is not one. */
export const totpCodeSchema = z.strictObject({
  code: z.string().min(1).max(20),
});

/** Enrolment carries no input at all, so any field makes the body malformed. */
export const totpEnrollSchema = z.strictObject({});
