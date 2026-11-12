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

export const emailStartSchema = z.strictObject({
  email: emailSchema,
  purpose: z.literal('register'),
  captchaToken: z.string().min(1).max(EMAIL_CAPTCHA_MAX_LENGTH),
});

export const emailVerifySchema = z.strictObject({
  email: emailSchema,
  purpose: z.enum(['register', 'login_device']),
  code: z.string().regex(/^[0-9]{6}$/),
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

export function parseEmailBody<T>(schema: z.ZodType<T>, body: unknown): T | null {
  const result = schema.safeParse(body);
  return result.success ? result.data : null;
}
