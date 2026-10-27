import {
  canonicalJson,
  computeAuditHash,
  isAuditHash,
  nextAuditTimestamp,
  serializeAuditPayload,
  type AuditHashPayload,
} from './audit-canonical';

const FIRST_ID = '0f8fad5b-d9cb-469f-a165-70867728950e';
const SECOND_ID = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

const payload = (overrides: Partial<AuditHashPayload> = {}): AuditHashPayload => ({
  id: FIRST_ID,
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
  actorId: '8c7a2f9e-4c43-4a63-9d3a-2f0f0a3b1c4d',
  actorRole: 'ADMIN',
  action: 'user.login',
  targetType: 'user',
  targetId: FIRST_ID,
  requestId: 'req-1',
  ipHash: 'a'.repeat(64),
  metadata: { b: 2, a: 1 },
  ...overrides,
});

describe('canonicalJson', () => {
  it('sorts object keys recursively', () => {
    expect(canonicalJson({ z: 1, a: { d: 4, b: [{ y: 2, x: 1 }] } })).toBe(
      '{"a":{"b":[{"x":1,"y":2}],"d":4},"z":1}',
    );
  });

  it('is stable when a jsonb round-trip changes key order', () => {
    const original = { outer: { zebra: true, alpha: 'x' }, list: [1, 2, 3] };
    const roundTripped = JSON.parse(
      JSON.stringify({ list: [1, 2, 3], outer: { alpha: 'x', zebra: true } }),
    ) as unknown;

    expect(canonicalJson(roundTripped)).toBe(canonicalJson(original));
  });

  it('maps undefined to null and dates to ISO strings', () => {
    expect(canonicalJson({ a: undefined, b: new Date('2026-01-01T00:00:00.000Z') })).toBe(
      '{"a":null,"b":"2026-01-01T00:00:00.000Z"}',
    );
  });

  it('rejects circular structures instead of looping', () => {
    const input: Record<string, unknown> = { name: 'loop' };
    input.self = input;

    expect(() => canonicalJson(input)).toThrow(/circular/i);
  });

  it('serialises payloads deterministically', () => {
    expect(serializeAuditPayload(payload())).toBe(
      serializeAuditPayload({ ...payload(), metadata: { a: 1, b: 2 } }),
    );
  });
});

describe('computeAuditHash', () => {
  it('produces a 64 character lowercase hex digest', () => {
    const hash = computeAuditHash(null, payload());

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(isAuditHash(hash)).toBe(true);
  });

  it('is deterministic', () => {
    expect(computeAuditHash(null, payload())).toBe(computeAuditHash(null, payload()));
  });

  it('chains to the previous hash', () => {
    const first = computeAuditHash(null, payload());
    const second = computeAuditHash(first, payload({ id: SECOND_ID }));

    expect(second).not.toBe(first);
    expect(computeAuditHash('b'.repeat(64), payload({ id: SECOND_ID }))).not.toBe(second);
  });

  it('changes when any covered field changes', () => {
    const base = computeAuditHash(null, payload());
    const variants: Array<Partial<AuditHashPayload>> = [
      { id: SECOND_ID },
      { createdAt: new Date('2026-01-01T00:00:00.001Z') },
      { actorId: null },
      { actorRole: 'USER' },
      { action: 'user.logout' },
      { targetType: null },
      { targetId: null },
      { requestId: null },
      { ipHash: null },
      { metadata: { a: 1 } },
    ];

    for (const variant of variants) {
      expect(computeAuditHash(null, payload(variant))).not.toBe(base);
    }
  });

  it('rejects a malformed previous hash instead of chaining garbage', () => {
    expect(() => computeAuditHash('not-a-hash', payload())).toThrow(/64 character/);
    expect(() => computeAuditHash('A'.repeat(64), payload())).toThrow(/64 character/);
  });
});

describe('isAuditHash', () => {
  it.each([
    ['a'.repeat(64), true],
    ['A'.repeat(64), false],
    ['a'.repeat(63), false],
    ['a'.repeat(65), false],
    ['g'.repeat(64), false],
    ['', false],
  ])('%s -> %s', (value, expected) => {
    expect(isAuditHash(value)).toBe(expected);
  });
});

describe('nextAuditTimestamp', () => {
  const now = new Date('2026-01-01T00:00:00.500Z');

  it('returns now for the first row', () => {
    expect(nextAuditTimestamp(null, now)).toEqual(now);
  });

  it('returns now when it is already after the previous row', () => {
    const previous = new Date('2026-01-01T00:00:00.000Z');

    expect(nextAuditTimestamp(previous, now)).toEqual(now);
  });

  it('moves one millisecond past the previous row when clocks collide', () => {
    const previous = new Date('2026-01-01T00:00:00.500Z');

    expect(nextAuditTimestamp(previous, now)).toEqual(new Date('2026-01-01T00:00:00.501Z'));
  });
});
