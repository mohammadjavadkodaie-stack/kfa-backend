import { createHmac } from 'node:crypto';

export function emailCodeKey(codeKey: Buffer, purpose: string, email: string): string {
  const digest = createHmac('sha256', codeKey).update(`key:${email}`, 'utf8').digest('hex');

  return `kfa:ecode:v1:${purpose}:${digest}`;
}

export function hashEmailCode(
  codeKey: Buffer,
  purpose: string,
  email: string,
  code: string,
): string {
  return createHmac('sha256', codeKey).update(`${purpose}|${email}|${code}`, 'utf8').digest('hex');
}
