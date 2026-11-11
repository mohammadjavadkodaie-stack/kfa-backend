import { hkdfSync } from 'node:crypto';

export class EmailCodeKeyMissingError extends Error {
  constructor() {
    super('EMAIL_CODE_HMAC_KEY is missing');
    this.name = 'EmailCodeKeyMissingError';
  }
}

function derive(secret: string | undefined, label: string): Buffer {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new EmailCodeKeyMissingError();
  }

  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.alloc(0), label, 32));
}

export function deriveEmailCodeKey(secret: string | undefined): Buffer {
  return derive(secret, 'kfa:email-code:v1');
}

export function deriveEmailProofKey(secret: string | undefined): Buffer {
  return derive(secret, 'kfa:email-proof:v1');
}
