import { createHmac } from 'node:crypto';
import {
  ACCESS_TOKEN_AUDIENCE,
  ACCESS_TOKEN_ISSUER,
  signAccessToken,
  verifyAccessToken,
} from './access-token';

const SECRET = 'unit-test-access-token-secret-0123456789abcdef';
const OTHER_SECRET = 'another-access-token-secret-0123456789abcdef';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '22222222-2222-4222-8222-222222222222';

const ISSUED_AT = 1_800_000_000;
const TTL = 600;

function sign(secret: string, signingInput: string): string {
  return createHmac('sha256', secret).update(signingInput, 'utf8').digest('base64url');
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/** Builds a token by hand so a test can lie about any part of it. */
function forge(
  options: {
    payload?: Record<string, unknown>;
    header?: Record<string, unknown>;
    secret?: string;
  } = {},
): string {
  const header = encode(options.header ?? { alg: 'HS256', typ: 'JWT' });
  const payload = encode(
    options.payload ?? {
      sub: USER_ID,
      sid: SESSION_ID,
      iat: ISSUED_AT,
      exp: ISSUED_AT + TTL,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    },
  );
  const signingInput = `${header}.${payload}`;

  return `${signingInput}.${sign(options.secret ?? SECRET, signingInput)}`;
}

function issueToken(overrides: { ttlSeconds?: number; secret?: string } = {}): string {
  return signAccessToken({
    secret: overrides.secret ?? SECRET,
    userId: USER_ID,
    sessionId: SESSION_ID,
    issuedAtSeconds: ISSUED_AT,
    ttlSeconds: overrides.ttlSeconds ?? TTL,
  });
}

describe('signAccessToken', () => {
  it('carries the user, the session and the configured lifetime', () => {
    const token = issueToken();

    expect(verifyAccessToken({ secret: SECRET, token, nowSeconds: ISSUED_AT })).toEqual({
      sub: USER_ID,
      sid: SESSION_ID,
      iat: ISSUED_AT,
      exp: ISSUED_AT + TTL,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    });
  });

  it('sends a fixed HS256 header', () => {
    const [header] = issueToken().split('.');

    expect(JSON.parse(Buffer.from(header as string, 'base64url').toString('utf8'))).toEqual({
      alg: 'HS256',
      typ: 'JWT',
    });
  });

  describe('verifyAccessToken', () => {
    it('accepts a token that was just signed', () => {
      expect(
        verifyAccessToken({ secret: SECRET, token: issueToken(), nowSeconds: ISSUED_AT }),
      ).not.toBeNull();
    });

    it('rejects a token whose signature was made with another secret', () => {
      const token = issueToken({ secret: OTHER_SECRET });

      expect(verifyAccessToken({ secret: SECRET, token, nowSeconds: ISSUED_AT })).toBeNull();
    });

    it('rejects a tampered payload even though the shape stays valid', () => {
      const [header, payload, signature] = issueToken().split('.');
      const claims = JSON.parse(
        Buffer.from(payload as string, 'base64url').toString('utf8'),
      ) as Record<string, unknown>;
      const tampered = `${header}.${encode({
        ...claims,
        sub: '44444444-4444-4444-8444-444444444444',
      })}.${signature}`;

      expect(
        verifyAccessToken({ secret: SECRET, token: tampered, nowSeconds: ISSUED_AT }),
      ).toBeNull();
    });

    it('rejects an expired token', () => {
      expect(
        verifyAccessToken({ secret: SECRET, token: issueToken(), nowSeconds: ISSUED_AT + TTL }),
      ).toBeNull();
    });

    it('rejects an unsigned token claiming `alg: none`', () => {
      const header = encode({ alg: 'none', typ: 'JWT' });
      const payload = encode({
        sub: USER_ID,
        sid: SESSION_ID,
        iat: ISSUED_AT,
        exp: ISSUED_AT + TTL,
        iss: ACCESS_TOKEN_ISSUER,
        aud: ACCESS_TOKEN_AUDIENCE,
      });

      expect(
        verifyAccessToken({
          secret: SECRET,
          token: `${header}.${payload}.`,
          nowSeconds: ISSUED_AT,
        }),
      ).toBeNull();
    });

    it('rejects a correctly signed token with a non-HS256 header', () => {
      expect(
        verifyAccessToken({
          secret: SECRET,
          token: forge({ header: { alg: 'HS512', typ: 'JWT' } }),
          nowSeconds: ISSUED_AT,
        }),
      ).toBeNull();
    });

    it('rejects a token with the wrong issuer', () => {
      expect(
        verifyAccessToken({
          secret: SECRET,
          token: forge({
            payload: {
              sub: USER_ID,
              sid: SESSION_ID,
              iat: ISSUED_AT,
              exp: ISSUED_AT + TTL,
              iss: 'somebody-else',
              aud: ACCESS_TOKEN_AUDIENCE,
            },
          }),
          nowSeconds: ISSUED_AT,
        }),
      ).toBeNull();
    });

    it('rejects a token with the wrong audience', () => {
      expect(
        verifyAccessToken({
          secret: SECRET,
          token: forge({
            payload: {
              sub: USER_ID,
              sid: SESSION_ID,
              iat: ISSUED_AT,
              exp: ISSUED_AT + TTL,
              iss: ACCESS_TOKEN_ISSUER,
              aud: 'someone-else',
            },
          }),
          nowSeconds: ISSUED_AT,
        }),
      ).toBeNull();
    });
  });

  it('never produces the same token for two different sessions', () => {
    const first = issueToken();
    const second = signAccessToken({
      secret: SECRET,
      userId: USER_ID,
      sessionId: '33333333-3333-4333-8333-333333333333',
      issuedAtSeconds: ISSUED_AT,
      ttlSeconds: TTL,
    });

    expect(first).not.toBe(second);
  });
});

describe('verifyAccessToken structural checks', () => {
  it.each([
    [
      'a missing expiry',
      { sub: USER_ID, sid: SESSION_ID, iat: ISSUED_AT, exp: undefined, iss: ACCESS_TOKEN_ISSUER },
    ],
    ['a non-uuid subject', { sub: 'admin', sid: SESSION_ID }],
    ['a non-uuid session', { sub: USER_ID, sid: 'session-1' }],
    ['a float expiry', { sub: USER_ID, sid: SESSION_ID, exp: ISSUED_AT + 0.5 }],
  ])('rejects %s', (_label, payload) => {
    const complete = {
      iat: ISSUED_AT,
      exp: ISSUED_AT + TTL,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
      ...payload,
    };

    expect(
      verifyAccessToken({
        secret: SECRET,
        token: forge({ payload: complete }),
        nowSeconds: ISSUED_AT,
      }),
    ).toBeNull();
  });

  it.each([
    ['an empty string', ''],
    ['two segments', 'aGVhZA.cGF5bG9hZA'],
    ['four segments', 'a.b.c.d'],
    ['non base64url characters', 'a b.c d.e f'],
    ['an oversized token', `${'a'.repeat(4_100)}.b.c`],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
  ])('rejects %s without throwing', (_label, token) => {
    expect(verifyAccessToken({ secret: SECRET, token, nowSeconds: ISSUED_AT })).toBeNull();
  });

  it('rejects a signature of the wrong length instead of throwing', () => {
    const [header, payload] = issueToken().split('.');

    expect(
      verifyAccessToken({
        secret: SECRET,
        token: `${header}.${payload}.${Buffer.alloc(16).toString('base64url')}`,
        nowSeconds: ISSUED_AT,
      }),
    ).toBeNull();
  });

  it('rejects a correctly signed payload that is not an object', () => {
    const header = encode({ alg: 'HS256', typ: 'JWT' });
    const payload = encode('just-a-string');
    const signingInput = `${header}.${payload}`;

    expect(
      verifyAccessToken({
        secret: SECRET,
        token: `${signingInput}.${sign(SECRET, signingInput)}`,
        nowSeconds: ISSUED_AT,
      }),
    ).toBeNull();
  });
});
