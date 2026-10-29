import { z } from 'zod';

/**
 * Request bodies for the OTP endpoints.
 *
 * Parsed with zod instead of a DTO class because every failure must collapse
 * into the same generic error: no field names, no reasons.
 */

export const OTP_PHONE_MAX_LENGTH = 20;
export const OTP_CAPTCHA_TOKEN_MAX_LENGTH = 2048;

const phoneSchema = z.string().max(OTP_PHONE_MAX_LENGTH);

export const otpStartSchema = z.strictObject({
  phone: phoneSchema,
  captchaToken: z.string().max(OTP_CAPTCHA_TOKEN_MAX_LENGTH),
});

export const otpVerifySchema = z.strictObject({
  phone: phoneSchema,
  code: z.string().regex(/^[0-9]{6}$/),
});

export type OtpStartInput = z.infer<typeof otpStartSchema>;
export type OtpVerifyInput = z.infer<typeof otpVerifySchema>;

/** Returns the parsed body, or null when it is not exactly the expected shape. */
export function parseBody<T>(schema: z.ZodType<T>, body: unknown): T | null {
  const result = schema.safeParse(body);

  return result.success ? result.data : null;
}
