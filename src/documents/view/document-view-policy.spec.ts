import { Role } from '../../auth/roles';
import {
  decideDocumentView,
  type DocumentFacts,
  type ViewDecision,
  type ViewerFacts,
} from './document-view-policy';

const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const VIEWER_ID = '22222222-2222-4222-8222-222222222222';

function viewer(overrides: Partial<ViewerFacts> = {}): ViewerFacts {
  return { id: VIEWER_ID, role: Role.USER, status: 'ACTIVE', ...overrides };
}

function document(overrides: Partial<DocumentFacts> = {}): DocumentFacts {
  return { ownerUserId: OWNER_ID, status: 'ACTIVE', ...overrides };
}

/** Only the two allowed shapes carry a basis; only the denied ones carry a reason. */
type Case = [string, ViewerFacts | null, DocumentFacts | null, boolean | undefined, ViewDecision];

const CASES: Case[] = [
  // The owner, and nothing can change that.
  [
    'the owner reading their own document',
    viewer({ id: OWNER_ID }),
    document(),
    undefined,
    {
      allowed: true,
      basis: 'owner',
    },
  ],
  [
    'the owner who is also staff, with no step-up',
    viewer({ id: OWNER_ID, role: Role.ADMIN }),
    document(),
    undefined,
    { allowed: true, basis: 'owner' },
  ],
  [
    'the owner with a step-up, still on the owner basis',
    viewer({ id: OWNER_ID, role: Role.OWNER }),
    document(),
    true,
    { allowed: true, basis: 'owner' },
  ],
  // Staff on a foreign document exists only with an explicit step-up.
  [
    'an admin reading a foreign document after a step-up',
    viewer({ role: Role.ADMIN }),
    document(),
    true,
    { allowed: true, basis: 'staff' },
  ],
  [
    'the owner-role account reading a foreign document after a step-up',
    viewer({ role: Role.OWNER }),
    document(),
    true,
    { allowed: true, basis: 'staff' },
  ],
  [
    'an admin without the step-up flag',
    viewer({ role: Role.ADMIN }),
    document(),
    undefined,
    { allowed: false, reason: 'staff_not_verified' },
  ],
  [
    'an admin with the step-up explicitly false',
    viewer({ role: Role.ADMIN }),
    document(),
    false,
    { allowed: false, reason: 'staff_not_verified' },
  ],
  // A verified step-up never widens a regular account.
  [
    'a user reading a foreign document with the step-up flag set',
    viewer({ role: Role.USER }),
    document(),
    true,
    { allowed: false, reason: 'not_owner' },
  ],
  [
    'an athlete reading a foreign document with the step-up flag set',
    viewer({ role: Role.ATHLETE }),
    document(),
    true,
    { allowed: false, reason: 'not_owner' },
  ],
  // The viewer is refused before the document is even looked at.
  ['a missing viewer', null, document(), true, { allowed: false, reason: 'viewer_missing' }],
  [
    'an unknown viewer role',
    viewer({ role: 'SUPERUSER' }),
    document(),
    true,
    { allowed: false, reason: 'unknown_viewer_role' },
  ],
  [
    'a lower-case role',
    viewer({ role: 'admin' }),
    document(),
    true,
    { allowed: false, reason: 'unknown_viewer_role' },
  ],
  [
    'a blocked viewer reading their own document',
    viewer({ id: OWNER_ID, status: 'BLOCKED' }),
    document(),
    undefined,
    { allowed: false, reason: 'viewer_not_active' },
  ],
  [
    'a blocked admin with a step-up',
    viewer({ role: Role.ADMIN, status: 'BLOCKED' }),
    document(),
    true,
    { allowed: false, reason: 'viewer_not_active' },
  ],
  [
    'an unknown role on an unknown document',
    viewer({ role: 'GHOST' }),
    null,
    true,
    { allowed: false, reason: 'unknown_viewer_role' },
  ],
  [
    'a blocked viewer on an unknown document',
    viewer({ status: 'BLOCKED' }),
    null,
    true,
    { allowed: false, reason: 'viewer_not_active' },
  ],
  // The document, once the viewer is known to be fine.
  ['a missing document', viewer(), null, true, { allowed: false, reason: 'document_missing' }],
  [
    'a soft-deleted document, for its owner',
    viewer({ id: OWNER_ID }),
    document({ status: 'DELETED' }),
    undefined,
    { allowed: false, reason: 'document_not_active' },
  ],
  [
    'a soft-deleted document, for an admin with a step-up',
    viewer({ role: Role.ADMIN }),
    document({ status: 'DELETED' }),
    true,
    { allowed: false, reason: 'document_not_active' },
  ],
];

describe('decideDocumentView', () => {
  it.each(CASES)('%s', (_label, subject, facts, staffVerified, expected) => {
    expect(decideDocumentView(subject, facts, staffVerified)).toEqual(expected);
  });

  it('is pure: the same facts always give the same decision', () => {
    const subject = viewer({ role: Role.ADMIN });
    const facts = document();

    expect(decideDocumentView(subject, facts, true)).toEqual(
      decideDocumentView(subject, facts, true),
    );
    // The inputs are not touched either.
    expect(subject).toEqual({ id: VIEWER_ID, role: Role.ADMIN, status: 'ACTIVE' });
    expect(facts).toEqual({ ownerUserId: OWNER_ID, status: 'ACTIVE' });
  });

  it('never leaks a reason when it allows a read', () => {
    for (const [, subject, facts, staffVerified, expected] of CASES) {
      const decision = decideDocumentView(subject, facts, staffVerified);

      expect(decision).toEqual(expected);

      if (decision.allowed) expect(Object.keys(decision).sort()).toEqual(['allowed', 'basis']);
      else expect(Object.keys(decision).sort()).toEqual(['allowed', 'reason']);
    }
  });

  it('needs exactly true, not merely truthy-for-a-role', () => {
    const subject = viewer({ role: Role.ADMIN });

    // `1` and `'true'` are what a sloppy caller passes: both must be refused.
    expect(decideDocumentView(subject, document(), 1 as unknown as boolean)).toEqual({
      allowed: false,
      reason: 'staff_not_verified',
    });
    expect(decideDocumentView(subject, document(), 'true' as unknown as boolean)).toEqual({
      allowed: false,
      reason: 'staff_not_verified',
    });
  });
});
