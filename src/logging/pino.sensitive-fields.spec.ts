import pino, { type DestinationStream } from 'pino';
import type { Env } from '../config/env';
import { buildPinoParams } from './pino.config';

const CANARIES = {
  password: 'canary-password',
  passwordHash: 'canary-password-hash',
  authorization: 'Bearer canary-authorization',
  cookie: 'canary-cookie',
  accessToken: 'canary-access-token',
  refreshToken: 'canary-refresh-token',
  emailCode: 'canary-email-otp',
  proofToken: 'canary-proof-token',
  totpSecret: 'canary-totp-secret',
  totpCode: 'canary-totp-code',
  email: 'canary@example.com',
  phone: '+15555550123',
  fileName: 'canary-identity.pdf',
  storageKey: 'documents/canary-identity.pdf',
  webhookSignature: 'canary-webhook-signature',
  nowPaymentsApiKey: 'canary-nowpayments-key',
  paypalApiKey: 'canary-paypal-key',
  NOWPAYMENTS_API_KEY: 'canary-nowpayments-key',
  NOWPAYMENTS_API_SECRET: 'canary-nowpayments-secret',
  PAYPAL_API_KEY: 'canary-paypal-key',
  PAYPAL_API_SECRET: 'canary-paypal-secret',
} as const;

function createLogger(): { logger: pino.Logger; lines: string[]; serializers: any } {
  const lines: string[] = [];
  const stream = {
    write: (line: string): void => {
      lines.push(line);
    },
  } as unknown as DestinationStream;
  const params = buildPinoParams({ LOG_LEVEL: 'debug' } as Env).pinoHttp as any;
  const logger = pino({ redact: params.redact, serializers: params.serializers }, stream);
  return { logger, lines, serializers: params.serializers };
}

describe('sensitive logger fields', () => {
  it('redacts canaries in normal logs', () => {
    const { logger, lines } = createLogger();
    logger.info(
      {
        ...CANARIES,
        objectKey: CANARIES.storageKey,
        req: {
          id: 'request-id',
          method: 'POST',
          url: '/test',
          headers: { authorization: CANARIES.authorization, cookie: CANARIES.cookie },
        },
        res: { headers: { 'set-cookie': CANARIES.cookie } },
        env: {
          NOWPAYMENTS_API_KEY: CANARIES.NOWPAYMENTS_API_KEY,
          NOWPAYMENTS_API_SECRET: CANARIES.NOWPAYMENTS_API_SECRET,
          PAYPAL_API_KEY: CANARIES.PAYPAL_API_KEY,
          PAYPAL_API_SECRET: CANARIES.PAYPAL_API_SECRET,
          UNLISTED_KEY: 'canary-unlisted-key',
          UNLISTED_SECRET: 'canary-unlisted-secret',
        },
      },
      'sensitive payload',
    );

    const output = lines.join('');
    for (const canary of Object.values(CANARIES)) expect(output).not.toContain(canary);
    expect(output).not.toContain('canary-unlisted-key');
    expect(output).not.toContain('canary-unlisted-secret');
  });

  it('redacts canaries in error logs', () => {
    const { logger, lines } = createLogger();
    logger.error(
      {
        err: new Error(CANARIES.password),
        ...CANARIES,
        objectKey: CANARIES.storageKey,
        storageKey: CANARIES.storageKey,
        request: {
          authorization: CANARIES.authorization,
          phone: CANARIES.phone,
          url: '/test',
          method: 'GET',
        },
      },
      'request failed',
    );

    const output = lines.join('');
    for (const canary of Object.values(CANARIES)) expect(output).not.toContain(canary);
  });

  it('serializers omit request and response secrets', () => {
    const { serializers } = createLogger();
    const request = serializers.req({
      id: 'request-id',
      method: 'POST',
      url: '/auth/signin',
      headers: { authorization: CANARIES.authorization, cookie: CANARIES.cookie },
      body: { password: CANARIES.password, email: CANARIES.email },
      ip: '203.0.113.10',
    });
    const response = serializers.res({
      statusCode: 200,
      headers: { 'set-cookie': CANARIES.cookie },
      body: { accessToken: CANARIES.accessToken },
    });

    expect(JSON.stringify(request)).not.toContain(CANARIES.password);
    expect(JSON.stringify(request)).not.toContain(CANARIES.authorization);
    expect(JSON.stringify(response)).not.toContain(CANARIES.accessToken);
    expect(JSON.stringify(response)).not.toContain(CANARIES.cookie);
  });
});
