import { createHmac } from 'node:crypto';
import {
  issueViewToken,
  verifyViewToken,
  VIEW_LINK_CONSUMPTION_TTL_SECONDS,
  VIEW_LINK_TTL_SECONDS,
  VIEW_TOKEN_MAX_LENGTH,
  type ViewTokenPayload,
} from './view-token';

/** Fixed, fake secret: never a real value, always recognisable as a fixture. */
const SECRET = 'test-only-view-token-secret-0123456789abcdef';
const OTHER_SECRET = 'test-only-other-view-token-secret-0123456789';
const DOCUMENT_ID = '11111111-1111-4111-8111-111111111111';
const VIEWER_ID = '22222222-2222-4222-8222-222222222222';
/** A fixed clock: 2026-03-01T00:00:00.000Z. */
const NOW_MS = Date.UTC(2026, 2, 1, 0, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1_000);

function issue(overrides: { staff?: boolean; secret?: string; nowMs?: number } = {}) {
  return issueViewToken({
    secret: overrides.secret ?? SECRET,
    documentId: DOCUMENT_ID,
    viewerUserId: VIEWER_ID,
    staff: overrides.staff ?? false,
    nowMs: overrides.nowMs ?? NOW_MS,
  });
}

function verify(token: unknown, options: { secret?: string; nowMs?: number } = {}) {
  return verifyViewToken({
    secret: options.secret ?? SECRET,
    token,
    nowMs: options.nowMs ?? NOW_MS,
  });
}

/** Re-signs an arbitrary payload, so a shape check can be tested on its own. */
function craft(payload: unknown, secret: string = SECRET): string {
  const segment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

  return `${segment}.${createHmac('sha256', secret).update(segment, 'utf8').digest('base64url')}`;
}

function validPayload(overrides: Record<string, unknown> = {}) {
  return {
    v: 1,
    jti: 'AAAAAAAAAAAAAAAAAAAAAA',
    documentId: DOCUMENT_ID,
    viewerUserId: VIEWER_ID,
    staff: false,
    exp: NOW_S + 60,
    ...overrides,
  };
}

describe('view-token', () => {
  it('keeps the link short-lived and the nonce slightly longer', () => {
    expect(VIEW_LINK_TTL_SECONDS).toBe(60);
    // The nonce must outlive the token, otherwise a live link could find nothing.
    expect(VIEW_LINK_CONSUMPTION_TTL_SECONDS).toBeGreaterThan(VIEW_LINK_TTL_SECONDS);
  });

  it('round-trips the claims it was given', () => {
    const issued = issue({ staff: true });
    const payload = verify(issued.token);

    expect(payload).toEqual({
      v: 1,
      jti: issued.jti,
      documentId: DOCUMENT_ID,
      viewerUserId: VIEWER_ID,
      staff: true,
      exp: NOW_S + VIEW_LINK_TTL_SECONDS,
    });
    expect(issued.exp).toBe(payload?.exp);
    // 16 random bytes, base64url: 22 characters, always.
    expect(issued.jti).toHaveLength(22);
  });

  it('mints a fresh nonce for every link', () => {
    const first = issue();
    const second = issue();

    expect(first.jti).not.toBe(second.jti);
    expect(first.token).not.toBe(second.token);
  });

  it('carries no object key, owner id or document content', () => {
    const { token } = issue();
    const payload = JSON.stringify(verify(token));

    expect(Object.keys(JSON.parse(payload) as object).sort()).toEqual([
      'documentId',
      'exp',
      'jti',
      'staff',
      'v',
      'viewerUserId',
    ]);
    expect(payload).not.toContain('national-id.png');
    expect(payload).not.toContain('test-only-plaintext');
  });

  it('accepts a link up to the last second of its lifetime', () => {
    const { token } = issue();

    expect(verify(token, { nowMs: (NOW_S + VIEW_LINK_TTL_SECONDS) * 1_000 - 1 })).not.toBeNull();
  });

  it('refuses a link from the second it expires', () => {
    const { token } = issue();

    expect(verify(token, { nowMs: (NOW_S + VIEW_LINK_TTL_SECONDS) * 1_000 })).toBeNull();
    expect(verify(token, { nowMs: (NOW_S + 3_600) * 1_000 })).toBeNull();
  });

  it('refuses a token signed with another secret', () => {
    const { token } = issue();

    expect(verify(token, { secret: OTHER_SECRET })).toBeNull();
  });

  it('refuses a tampered payload', () => {
    const { token } = issue();
    const [payloadSegment, signatureSegment] = token.split('.') as [string, string];
    const decoded = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    const forged = Buffer.from(
      JSON.stringify({ ...decoded, documentId: '33333333-3333-4333-8333-333333333333' }),
      'utf8',
    ).toString('base64url');

    expect(verify(`${forged}.${signatureSegment}`)).toBeNull();
  });

  it('refuses a swapped signature', () => {
    const first = issue();
    const second = issue();
    const [firstPayload] = first.token.split('.') as [string, string];
    const [, secondSignature] = second.token.split('.') as [string, string];

    expect(verify(`${firstPayload}.${secondSignature}`)).toBeNull();
  });

  it.each([
    ['an empty string', ''],
    ['not a token', 'not-a-token'],
    ['three segments', 'a.b.c'],
    ['an empty signature', 'payload.'],
    ['a character outside base64url', 'pay+load.signature'],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['an object', { token: 'a.b' }],
    ['an oversized string', 'a'.repeat(VIEW_TOKEN_MAX_LENGTH + 1)],
  ])('refuses %s', (_label, token) => {
    expect(verify(token)).toBeNull();
  });

  it('refuses a short signature even when the pattern is right', () => {
    const [payloadSegment] = issue().token.split('.') as [string, string];

    expect(verify(`${payloadSegment}.AAAA`)).toBeNull();
  });

  it.each([
    ['an unknown version', { v: 2 }],
    ['a short nonce', { jti: 'short' }],
    ['a nonce with padding characters', { jti: `${'A'.repeat(20)}==` }],
    ['a document id that is not a uuid', { documentId: '../../etc/passwd' }],
    ['a viewer id that is not a uuid', { viewerUserId: 'anonymous' }],
    ['a staff flag that is not a boolean', { staff: 'true' }],
    ['a non-integer expiry', { exp: NOW_S + 60.5 }],
    ['a string expiry', { exp: String(NOW_S + 60) }],
    ['a missing expiry', { exp: undefined }],
  ])('refuses a correctly signed payload with %s', (_label, overrides) => {
    // Signed with the real secret: only the shape can stop it.
    expect(verify(craft(validPayload(overrides)))).toBeNull();
  });

  it.each([
    ['a string', '"a string"'],
    ['a number', '42'],
    ['an array', '[]'],
    ['null', 'null'],
  ])('refuses a correctly signed %s payload', (_label, json) => {
    const segment = Buffer.from(json, 'utf8').toString('base64url');
    const signature = createHmac('sha256', SECRET).update(segment, 'utf8').digest('base64url');

    expect(verify(`${segment}.${signature}`)).toBeNull();
  });

  it('accepts a correctly signed payload built by another issuer', () => {
    // Proves the shape rules, not the issuer, are what decides.
    expect(verify(craft(validPayload()))).toEqual(validPayload());
  });

  it('never reports why a token was refused', () => {
    const expired = issue().token;

    // Expired, tampered and unsigned all look the same from outside: null.
    expect(verify(expired, { nowMs: (NOW_S + 3_600) * 1_000 })).toBeNull();
    expect(verify(`${expired}x`)).toBeNull();
  });
});
