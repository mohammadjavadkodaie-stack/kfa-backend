import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import { PROOF_NONCE_STORE, type ProofNonceStore } from '../otp/proof-token';
import { normalizeEmail } from './email';
import { type EmailCodePurpose } from './email.provider';
import { deriveEmailProofKey } from './email-keys';

export const EMAIL_PROOF_TTL_SECONDS = 600;
export const EMAIL_PROOF_TOKEN_MAX_LENGTH = 2048;
const SIGNATURE_LENGTH = 32;
const HASH_PATTERN = /^[0-9a-f]{64}$/u;
const JTI_PATTERN = /^[0-9a-f-]{36}$/u;
const EMAIL_PURPOSES: ReadonlySet<EmailCodePurpose> = new Set([
  'register',
  'login_device',
  'password_reset',
  'email_change_new',
  'email_change_old',
]);

interface EmailProofPayload {
  readonly v: 3;
  readonly k: 'email';
  readonly sh: string;
  readonly jti: string;
  readonly purpose: EmailCodePurpose;
  readonly exp: number;
}

function sign(key: Buffer, value: string): Buffer {
  return createHmac('sha256', key).update(value, 'utf8').digest();
}

function equal(left: string | Buffer, right: string | Buffer): boolean {
  const a = Buffer.isBuffer(left) ? left : Buffer.from(left, 'utf8');
  const b = Buffer.isBuffer(right) ? right : Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function isPayload(value: unknown): value is EmailProofPayload {
  if (typeof value !== 'object' || value === null) return false;
  const payload = value as Record<string, unknown>;
  return (
    payload.v === 3 &&
    payload.k === 'email' &&
    typeof payload.sh === 'string' &&
    HASH_PATTERN.test(payload.sh) &&
    typeof payload.jti === 'string' &&
    JTI_PATTERN.test(payload.jti) &&
    typeof payload.purpose === 'string' &&
    EMAIL_PURPOSES.has(payload.purpose as EmailCodePurpose) &&
    typeof payload.exp === 'number' &&
    Number.isInteger(payload.exp)
  );
}

function unavailable(): ServiceUnavailableException {
  return new ServiceUnavailableException();
}

@Injectable()
export class EmailProofService {
  private readonly secret: string | undefined;

  constructor(
    @Inject(ENV) env: Pick<Env, 'EMAIL_CODE_HMAC_KEY'>,
    @Inject(PROOF_NONCE_STORE) private readonly store: ProofNonceStore | null,
  ) {
    this.secret = env.EMAIL_CODE_HMAC_KEY;
  }

  async issueEmailProof(input: {
    readonly email: string;
    readonly purpose: EmailCodePurpose;
    readonly nowMs?: number;
  }): Promise<string> {
    const normalized = normalizeEmail(input.email);
    const store = this.store;
    if (normalized === null || store === null) throw unavailable();

    let key: Buffer;
    try {
      key = deriveEmailProofKey(this.secret);
    } catch {
      throw unavailable();
    }

    const jti = randomUUID();
    const payload: EmailProofPayload = {
      v: 3,
      k: 'email',
      sh: sign(key, `email-proof:${normalized}`).toString('hex'),
      jti,
      purpose: input.purpose,
      exp: Math.floor((input.nowMs ?? Date.now()) / 1_000) + EMAIL_PROOF_TTL_SECONDS,
    };

    try {
      if (!(await store.put(jti, normalized, EMAIL_PROOF_TTL_SECONDS))) throw new Error('nonce');
    } catch {
      throw unavailable();
    }

    const payloadSegment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    return `${payloadSegment}.${sign(key, payloadSegment).toString('base64url')}`;
  }

  async consumeEmailProof(input: {
    readonly proof: unknown;
    readonly purpose: EmailCodePurpose;
    readonly nowMs?: number;
  }): Promise<string | null> {
    if (
      typeof input.proof !== 'string' ||
      input.proof.length === 0 ||
      input.proof.length > EMAIL_PROOF_TOKEN_MAX_LENGTH
    ) {
      return null;
    }

    let key: Buffer;
    try {
      key = deriveEmailProofKey(this.secret);
    } catch {
      throw unavailable();
    }

    const parts = input.proof.split('.');
    if (parts.length !== 2) return null;
    const [payloadSegment, signatureSegment] = parts as [string, string];
    let signature: Buffer;
    try {
      signature = Buffer.from(signatureSegment, 'base64url');
    } catch {
      return null;
    }
    if (signature.length !== SIGNATURE_LENGTH || !equal(signature, sign(key, payloadSegment)))
      return null;

    let decoded: unknown;
    try {
      decoded = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (!isPayload(decoded)) return null;
    if (decoded.exp <= Math.floor((input.nowMs ?? Date.now()) / 1_000)) return null;
    if (!equal(decoded.purpose, input.purpose)) return null;

    if (this.store === null) throw unavailable();

    let normalized: string | null;
    try {
      normalized = await this.store.take(decoded.jti);
    } catch {
      throw unavailable();
    }
    if (normalized === null || normalizeEmail(normalized) !== normalized) return null;
    return equal(sign(key, `email-proof:${normalized}`).toString('hex'), decoded.sh)
      ? normalized
      : null;
  }
}
