import { z } from 'zod';
import {
  AUTH_DEVICE_NAME_MAX_LENGTH,
  AUTH_PROOF_MAX_LENGTH,
  deviceNameSchema,
  usernameSchema,
} from '../auth.schema';

export const EMAIL_MAX_LENGTH = 254;
export const EMAIL_CAPTCHA_MAX_LENGTH = 2048;

const emailSchema = z.string().min(3).max(EMAIL_MAX_LENGTH);
const passwordSchema = z.string().min(1).max(512);
const proofSchema = z.string().min(1).max(AUTH_PROOF_MAX_LENGTH);
const localeSchema = z.enum(['en', 'fa', 'tr', 'ar']).optional();

export const emailStartSchema = z.strictObject({
  email: emailSchema,
  purpose: z.literal('register'),
  captchaToken: z.string().min(1).max(EMAIL_CAPTCHA_MAX_LENGTH),
  locale: localeSchema,
});

export const emailVerifySchema = z.strictObject({
  email: emailSchema,
  purpose: z.enum(['register', 'login_device', 'password_reset']),
  code: z.string().regex(/^[0-9]{6}$/),
});

/**
 * Step 1 of "I forgot my password": mail a reset code.
 *
 * Same shape as the register start - same captcha, same email - because the
 * endpoint must answer identically for an address with an account and one
 * without.
 */
export const passwordResetStartSchema = z.strictObject({
  email: emailSchema,
  captchaToken: z.string().min(1).max(EMAIL_CAPTCHA_MAX_LENGTH),
  locale: localeSchema,
});

/** Step 2: spend the emailed proof on a new password. */
export const passwordResetSchema = z.strictObject({
  proof: proofSchema,
  newPassword: z.string().min(1).max(512),
});

export const emailSignUpSchema = z.strictObject({
  proof: proofSchema,
  username: usernameSchema,
  password: passwordSchema,
  deviceName: deviceNameSchema,
});

export const emailSignInSchema = z.strictObject({
  email: emailSchema,
  password: passwordSchema,
  proof: proofSchema.optional(),
  deviceName: deviceNameSchema,
});

export type EmailStartInput = z.infer<typeof emailStartSchema>;
export type EmailVerifyInput = z.infer<typeof emailVerifySchema>;
export type EmailSignUpInput = z.infer<typeof emailSignUpSchema>;
export type EmailSignInInput = z.infer<typeof emailSignInSchema>;
export type PasswordResetStartInput = z.infer<typeof passwordResetStartSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;

export function parseEmailBody<T>(schema: z.ZodType<T>, body: unknown): T | null {
  const result = schema.safeParse(body);
  return result.success ? result.data : null;
}
