import { z } from 'zod';

/**
 * Request bodies for the session endpoints.
 *
 * Register and login carry no phone of their own: the number comes from the OTP
 * proof, so a caller cannot create a session for a number they do not control.
 */

export const AUTH_PROOF_MAX_LENGTH = 2048;
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 30;
/** Matches the label length check of the devices table. */
export const AUTH_DEVICE_NAME_MAX_LENGTH = 100;

/** Letters, digits and underscore; stored lowercased so `Ivan` cannot shadow `ivan`. */
export const usernameSchema = z
  .string()
  .min(USERNAME_MIN_LENGTH)
  .max(USERNAME_MAX_LENGTH)
  .regex(/^[A-Za-z0-9_]+$/)
  .transform((value) => value.toLowerCase());

const proofSchema = z.string().min(1).max(AUTH_PROOF_MAX_LENGTH);

/** Optional label for the device list; the `User-Agent` is only the fallback. */
const deviceNameSchema = z.string().trim().min(1).max(AUTH_DEVICE_NAME_MAX_LENGTH).optional();

export const registerSchema = z.strictObject({
  proof: proofSchema,
  username: usernameSchema,
  deviceName: deviceNameSchema,
});

export const loginSchema = z.strictObject({
  proof: proofSchema,
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

/** Returns the parsed body, or null when it is not exactly the expected shape. */
export function parseAuthBody<T>(schema: z.ZodType<T>, body: unknown): T | null {
  const result = schema.safeParse(body);

  return result.success ? result.data : null;
}
