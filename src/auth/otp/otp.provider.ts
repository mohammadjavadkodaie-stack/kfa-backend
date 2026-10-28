export interface OtpContext {
  readonly purpose?: string;
}

/** A provider may verify remotely, or return a reference to a locally stored hash challenge. */
export interface OtpProvider {
  start(phoneE164: string, context: OtpContext): Promise<{ challengeRef: string | null }>;
  check(phoneE164: string, code: string, challengeRef: string | null): Promise<boolean>;
}

export const OTP_PROVIDER = Symbol('OTP_PROVIDER');

export class FakeOtpProvider implements OtpProvider {
  async start(_phoneE164: string, _context: OtpContext): Promise<{ challengeRef: string | null }> {
    return { challengeRef: null };
  }

  async check(_phoneE164: string, code: string, _challengeRef: string | null): Promise<boolean> {
    return code === '123456';
  }
}
