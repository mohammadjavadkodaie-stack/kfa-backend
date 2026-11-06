import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { timingSafeEqual } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { PROOF_NONCE_STORE, type ProofNonceStore } from '../../auth/otp/proof-token';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { parseRole } from '../../auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../../auth/session.repository';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import { DocumentCryptoService } from '../document-crypto.service';
import { DOCUMENT_STORAGE, type DocumentStorage } from '../document-storage';
import {
  IDENTITY_DOCUMENT_REPOSITORY,
  type DocumentContentType,
  type IdentityDocumentRecord,
  type IdentityDocumentRepository,
} from '../records/identity-document.repository';
import {
  decideDocumentView,
  type DocumentFacts,
  type ViewBasis,
  type ViewDecision,
  type ViewDenialReason,
  type ViewerFacts,
} from './document-view-policy';
import {
  issueViewToken,
  verifyViewToken,
  VIEW_LINK_CONSUMPTION_TTL_SECONDS,
  VIEW_LINK_TTL_SECONDS,
} from './view-token';

/**
 * A single-use link to one identity document.
 *
 * Nothing here is a route: the caller supplies the authenticated subject and its
 * own `staffVerified` assertion, because only the route layer knows whether
 * StaffGate and a step-up were enforced for this request.
 *
 * The two operations share one contract:
 *
 * - the decision is made from fresh rows on every call, never from the token;
 * - the trail is written before any byte is read, so an unaudited access cannot
 *   happen;
 * - every refusal is the same generic `NotFoundException`, so a viewer learns
 *   neither which documents exist nor who owns them;
 * - a missing secret or a missing one-time store turns the feature off (503)
 *   rather than degrading to replayable links.
 */

/** The accountable actions, as they appear in the audit chain. */
export const DOCUMENT_VIEW_ACTIONS = {
  LINK_ISSUED: 'document.view_link_issued',
  VIEWED: 'document.viewed',
  DENIED: 'authz.denied',
} as const;

export type DocumentViewAction = (typeof DOCUMENT_VIEW_ACTIONS)[keyof typeof DOCUMENT_VIEW_ACTIONS];

const AUDIT_TARGET_TYPE = 'identity_document';
/** The action a denial is about; a fixed string, never caller input. */
const VIEWED_ACTION = 'document.view';
/** Written instead of a value that is not a known role. */
const UNKNOWN = 'unknown';

/** What the route layer asks for. `staffVerified` is its own assertion. */
export interface IssueViewLinkRequest {
  readonly documentId: string;
  /** True only when StaffGate and StepUp were enforced for this caller. */
  readonly staffVerified?: boolean;
}

/** What the caller receives: a link, and how long it lives. No document data. */
export interface DocumentViewLink {
  readonly token: string;
  readonly expiresInSeconds: number;
}

/** The plaintext a redeemed link yields, with what it was stored as. */
export interface DocumentViewBytes {
  readonly bytes: Buffer;
  readonly contentType: DocumentContentType;
  /** The length of the bytes actually returned, not the row's claim about them. */
  readonly sizeBytes: number;
}

function notFound(): NotFoundException {
  // Generic on purpose: a foreign document and a missing one answer alike.
  return new NotFoundException();
}

function unavailable(): ServiceUnavailableException {
  // Generic on purpose: callers never learn which dependency failed.
  return new ServiceUnavailableException();
}

/** Length-checked, constant-time comparison of two UTF-8 strings. */
function sameValue(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');

  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

/** The policy reads facts, not rows: a row that is gone is simply null. */
function factsOf(document: IdentityDocumentRecord | null): DocumentFacts | null {
  return document === null ? null : { ownerUserId: document.ownerUserId, status: document.status };
}

/** The reason a refusal is recorded with; a denial always carries one. */
function reasonOf(decision: ViewDecision): ViewDenialReason {
  return decision.allowed ? 'document_missing' : decision.reason;
}

@Injectable()
export class DocumentViewService {
  private readonly secret: string | undefined;

  constructor(
    @Inject(ENV) env: Pick<Env, 'DOCUMENT_VIEW_TOKEN_SECRET'>,
    @Inject(IDENTITY_DOCUMENT_REPOSITORY) private readonly documents: IdentityDocumentRepository,
    @Inject(SESSION_REPOSITORY) private readonly accounts: SessionRepository,
    // The same one-time store the OTP proof uses: SET NX to remember, GETDEL to
    // spend. Null when no shared store is configured, which fails closed below.
    @Inject(PROOF_NONCE_STORE) private readonly nonces: ProofNonceStore | null,
    private readonly crypto: DocumentCryptoService,
    @Inject(DOCUMENT_STORAGE) private readonly storage: DocumentStorage,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.secret = env.DOCUMENT_VIEW_TOKEN_SECRET;
  }

  /**
   * Decides one read against fresh rows and, when it is allowed, returns a link
   * that opens exactly that document once.
   *
   * Order: load the document, decide, record the issue, then sign. Without the
   * trail there is no link - an access nobody could account for is exactly what
   * the chain exists to prevent.
   */
  async issueLink(
    viewer: PolicySubject,
    request: IssueViewLinkRequest,
    nowMs: number = Date.now(),
  ): Promise<DocumentViewLink> {
    const secret = this.secret;
    const nonces = this.nonces;

    if (secret === undefined || nonces === null) throw unavailable();

    const document = await this.loadDocument(request.documentId);
    // The guard resolved `viewer` for this request and already refused a blocked
    // account, so the caller here is an active one.
    const decision = decideDocumentView(
      { id: viewer.id, role: String(viewer.role), status: 'ACTIVE' },
      factsOf(document),
      request.staffVerified,
    );

    if (!decision.allowed || document === null) {
      await this.recordDenial(viewer.id, String(viewer.role), reasonOf(decision));
      throw notFound();
    }

    await this.recordIssue(viewer.id, String(viewer.role), document, decision.basis);

    const issued = issueViewToken({
      secret,
      documentId: document.id,
      viewerUserId: viewer.id,
      staff: decision.basis === 'staff',
      nowMs,
    });

    // The nonce remembers who it was minted for; redemption compares the two.
    try {
      if (!(await nonces.put(issued.jti, viewer.id, VIEW_LINK_CONSUMPTION_TTL_SECONDS))) {
        throw new Error('view nonce collision');
      }
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.LINK_ISSUED, stage: 'store' },
        'document view link not stored',
      );
      throw unavailable();
    }

    return { token: issued.token, expiresInSeconds: VIEW_LINK_TTL_SECONDS };
  }

  /**
   * Spends one link and returns the document's plaintext.
   *
   * Order: verify the token, spend the nonce, reload the document and the viewer,
   * decide again, record the view, then read and decrypt. The second decision is
   * not a repeat of the first - a role change, a block or a deleted document
   * since the issue is caught here - and the row describing the read exists
   * before any byte leaves.
   */
  async redeem(token: unknown, nowMs: number = Date.now()): Promise<DocumentViewBytes> {
    const secret = this.secret;
    const nonces = this.nonces;

    if (secret === undefined || nonces === null) throw unavailable();

    // 1. Signature and expiry only: a forged token must never spend a real nonce.
    const payload = verifyViewToken({ secret, token, nowMs });

    if (payload === null) throw notFound();

    // 2. Single use: reading the nonce and deleting it are one step, so two
    //    simultaneous redemptions cannot both find it.
    let stored: string | null;

    try {
      stored = await nonces.take(payload.jti);
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.VIEWED, stage: 'store' },
        'document view link not spent',
      );
      throw unavailable();
    }

    if (stored === null || !sameValue(stored, payload.viewerUserId)) throw notFound();

    // 3. Fresh rows: the token names them, it does not describe them.
    const document = await this.loadDocument(payload.documentId);
    const viewer = await this.loadViewer(payload.viewerUserId);
    const decision = decideDocumentView(viewer, factsOf(document), payload.staff);

    if (!decision.allowed) {
      await this.recordDenial(payload.viewerUserId, viewer?.role ?? UNKNOWN, decision.reason);
      throw notFound();
    }

    // The decision can only be allowed when both rows exist; this keeps the
    // types honest without adding a second rule.
    if (document === null || viewer === null) throw notFound();

    // 4. The trail comes before the bytes.
    await this.recordView(viewer.id, viewer.role, document, decision.basis);

    // 5 and 6. Read the blob, then open the envelope with its own object key.
    const bytes = await this.unseal(document, await this.read(document));

    return { bytes, contentType: document.contentType, sizeBytes: bytes.length };
  }

  /** One ACTIVE document, or null: a soft-deleted row is not viewable either. */
  private async loadDocument(id: string): Promise<IdentityDocumentRecord | null> {
    try {
      return await this.documents.findActiveById(id);
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.VIEWED, stage: 'document' },
        'document view lookup failed',
      );
      throw unavailable();
    }
  }

  /** The viewer as the database holds them right now, role and status included. */
  private async loadViewer(userId: string): Promise<ViewerFacts | null> {
    try {
      const account = await this.accounts.findUserById(userId);

      return account === null
        ? null
        : { id: account.id, role: String(account.role), status: account.status };
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.VIEWED, stage: 'viewer' },
        'document view viewer lookup failed',
      );
      throw unavailable();
    }
  }

  /** Reads the ciphertext; the object key is never logged, echoed or stored. */
  private async read(document: IdentityDocumentRecord): Promise<Buffer> {
    try {
      return await this.storage.get(document.objectKey);
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.VIEWED, stage: 'storage' },
        'document view storage read failed',
      );
      throw unavailable();
    }
  }

  /** Opens the envelope; the object key is the AAD, so a moved blob fails here. */
  private async unseal(document: IdentityDocumentRecord, ciphertext: Buffer): Promise<Buffer> {
    try {
      return await this.crypto.decrypt(
        {
          ciphertext,
          iv: document.iv,
          authTag: document.authTag,
          wrappedDek: document.wrappedDek,
          keyId: document.keyId,
        },
        document.objectKey,
      );
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.VIEWED, stage: 'decrypt' },
        'document view decryption failed',
      );
      throw unavailable();
    }
  }

  /**
   * The row for an issued link. Fail closed: a link nobody can account for is
   * never handed out.
   */
  private async recordIssue(
    actorId: string,
    role: string,
    document: IdentityDocumentRecord,
    basis: ViewBasis,
  ): Promise<void> {
    await this.appendTrail(DOCUMENT_VIEW_ACTIONS.LINK_ISSUED, actorId, role, document, basis);
  }

  /** The row for a completed read. Fail closed: no trail, no bytes. */
  private async recordView(
    actorId: string,
    role: string,
    document: IdentityDocumentRecord,
    basis: ViewBasis,
  ): Promise<void> {
    await this.appendTrail(DOCUMENT_VIEW_ACTIONS.VIEWED, actorId, role, document, basis);
  }

  /**
   * Names, roles and a role-based basis only: the metadata can never carry the
   * object key, a hash, a file name or any of the bytes.
   */
  private async appendTrail(
    action: DocumentViewAction,
    actorId: string,
    role: string,
    document: IdentityDocumentRecord,
    basis: ViewBasis,
  ): Promise<void> {
    const viewerRole = parseRole(role) ?? UNKNOWN;

    try {
      await this.audit.record({
        action,
        actorId,
        actorRole: viewerRole,
        targetType: AUDIT_TARGET_TYPE,
        targetId: document.id,
        metadata: {
          documentId: document.id,
          kind: document.kind,
          viewerRole,
          accessBasis: basis,
        },
      });
    } catch {
      // Only the action and the stage are logged: no id, no key, no message from
      // the exception.
      this.logger.warn({ action, stage: 'audit' }, 'document view not recorded');
      throw unavailable();
    }
  }

  /**
   * The row for a refusal. It carries no document id and no target, so a foreign
   * document and a missing one leave exactly the same trace, and a refusal is
   * best effort: it stands whether or not the row was written.
   */
  private async recordDenial(
    actorId: string,
    role: string,
    reason: ViewDenialReason,
  ): Promise<void> {
    const actorRole = parseRole(role) ?? UNKNOWN;

    this.logger.warn({ action: DOCUMENT_VIEW_ACTIONS.DENIED, reason }, 'document view denied');

    try {
      await this.audit.record({
        action: DOCUMENT_VIEW_ACTIONS.DENIED,
        actorId,
        actorRole,
        targetType: AUDIT_TARGET_TYPE,
        metadata: { actorRole, action: VIEWED_ACTION },
      });
    } catch {
      this.logger.warn(
        { action: DOCUMENT_VIEW_ACTIONS.DENIED, stage: 'audit' },
        'document view denial not recorded',
      );
    }
  }
}
