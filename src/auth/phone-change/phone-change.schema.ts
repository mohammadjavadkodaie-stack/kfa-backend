import { z } from 'zod';
import { OTP_CAPTCHA_TOKEN_MAX_LENGTH, OTP_PHONE_MAX_LENGTH } from '../otp/otp.schema';
import { PROOF_TOKEN_MAX_LENGTH } from '../otp/proof-token';

/**
 * Request bodies for the authenticated phone-change flow.
 *
 * None of them carries a purpose and none carries the current number: the
 * server picks the purpose (`phone_change_new` / `phone_change_old`) and reads
 * the old number from the database. `strictObject` turns any attempt to supply
 * either one into a plain malformed body.
 */

const codeSchema = z.string().regex(/^[0-9]{6}$/);
const proofSchema = z.string().min(1).max(PROOF_TOKEN_MAX_LENGTH);

export const phoneChangeStartSchema = z.strictObject({
  phone: z.string().max(OTP_PHONE_MAX_LENGTH),
  captchaToken: z.string().max(OTP_CAPTCHA_TOKEN_MAX_LENGTH),
});

/** The new number is echoed because it is not stored anywhere yet. */
export const phoneChangeVerifyNewSchema = z.strictObject({
  phone: z.string().max(OTP_PHONE_MAX_LENGTH),
  code: codeSchema,
});

/** Only a code: the current number comes from the database. */
export const phoneChangeVerifyOldSchema = z.strictObject({
  code: codeSchema,
});

export const phoneChangeConfirmSchema = z.strictObject({
  proofNew: proofSchema,
  proofOld: proofSchema,
});
