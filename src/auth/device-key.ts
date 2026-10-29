import { createHmac, randomBytes } from 'node:crypto';

/**
 * Optional client device identifier (`X-Device-Key`).
 *
 * A session is bound to the hash of the key that created it, so a refresh token
 * stolen from one browser cannot be rotated from another one.
 */

export const DEVICE_KEY_HEADER = 'x-device-key';
export const DEVICE_KEY_MAX_LENGTH = 256;

export function readDeviceKey(value: string | string[] | undefined): string | null {
  const candidate = Array.isArray(value) ? value[0] : value;

  return typeof candidate === 'string' &&
    candidate.length > 0 &&
    candidate.length <= DEVICE_KEY_MAX_LENGTH
    ? candidate
    : null;
}

/**
 * HMAC-SHA256 of the raw key. The user id is mixed in because the device hash
 * is unique in the database while two accounts may share one browser.
 */
export function hashDeviceKey(secret: string, userId: string, rawDeviceKey: string): string {
  return createHmac('sha256', secret)
    .update(`device:${userId}:${rawDeviceKey}`, 'utf8')
    .digest('hex');
}

/** Client sent no key: the device row is bound to nothing (random, single use). */
export function ephemeralDeviceKey(): string {
  return randomBytes(32).toString('base64url');
}
