import { isStaffRole, parseRole } from '../../auth/roles';

/**
 * Who may read one identity document.
 *
 * Pure: no I/O, no clock, no Nest, so the whole rule set is testable as a table.
 * The service hands it what the database reported for this request, which is why
 * a role change, a block or a deletion since the link was issued is already part
 * of the answer.
 *
 * Two bases exist and nothing else does: the owner reading their own document,
 * and staff reading someone else's after the route layer enforced StaffGate and a
 * step-up. `staffVerified` is the caller's assertion about that enforcement -
 * this module never infers it from a role, and only `true` counts.
 */

/** The only two reasons a document is ever handed out. */
export type ViewBasis = 'owner' | 'staff';

/** The viewer, as the database holds them right now. */
export interface ViewerFacts {
  readonly id: string;
  /** As stored; re-parsed here so an unknown value is refused, not guessed. */
  readonly role: string;
  /** A blocked account reads nothing, its own documents included. */
  readonly status: 'ACTIVE' | 'BLOCKED';
}

/** The document, as the database holds it right now. */
export interface DocumentFacts {
  readonly ownerUserId: string;
  readonly status: 'ACTIVE' | 'DELETED';
}

/**
 * Internal denial codes. They exist for logs and tests only and are never sent
 * to the client: every refusal is the same generic 404.
 */
export type ViewDenialReason =
  | 'viewer_missing'
  | 'unknown_viewer_role'
  | 'viewer_not_active'
  | 'document_missing'
  | 'document_not_active'
  | 'staff_not_verified'
  | 'not_owner';

export type ViewDecision =
  | { readonly allowed: true; readonly basis: ViewBasis }
  | { readonly allowed: false; readonly reason: ViewDenialReason };

function deny(reason: ViewDenialReason): ViewDecision {
  return { allowed: false, reason };
}

/**
 * Decides one read. Deny is the default everywhere: an unknown role, a missing
 * row and a role that no rule covers are all refused.
 *
 * The order is deliberate. The viewer is checked first so a blocked account is
 * refused whatever it asks for; the document second, so a missing row and a
 * foreign row end in the same refusal and a viewer cannot probe which documents
 * exist.
 */
export function decideDocumentView(
  viewer: ViewerFacts | null,
  document: DocumentFacts | null,
  staffVerified: boolean | undefined,
): ViewDecision {
  if (viewer === null) return deny('viewer_missing');

  const viewerRole = parseRole(viewer.role);

  if (viewerRole === null) return deny('unknown_viewer_role');
  if (viewer.status !== 'ACTIVE') return deny('viewer_not_active');

  if (document === null) return deny('document_missing');
  if (document.status !== 'ACTIVE') return deny('document_not_active');

  // Ownership is the whole rule for a regular account and the first rule for
  // staff: reading one's own document needs neither StaffGate nor a step-up.
  if (document.ownerUserId === viewer.id) return { allowed: true, basis: 'owner' };

  if (isStaffRole(viewerRole)) {
    return staffVerified === true ? { allowed: true, basis: 'staff' } : deny('staff_not_verified');
  }

  return deny('not_owner');
}
