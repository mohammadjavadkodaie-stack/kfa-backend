import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { PROOF_NONCE_STORE, type ProofNonceStore } from '../../auth/proof/proof-nonce.store';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { isStaffRole, parseRole } from '../../auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../../auth/session.repository';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';
import { DocumentCryptoService } from '../../documents/document-crypto.service';
import { DOCUMENT_STORAGE, type DocumentStorage } from '../../documents/document-storage';
import {
  issueViewToken,
  verifyViewToken,
  VIEW_LINK_CONSUMPTION_TTL_SECONDS,
  VIEW_LINK_TTL_SECONDS,
} from '../../documents/view/view-token';
import type {
  PhotoContentType,
  ProfilePhotoRecord,
  ProfilePhotoStatus,
} from './profile-photo.repository';
import type {
  ApprovedPhotoSummary,
  ProfilePhotoViewRecord,
  ProfilePhotoViewRepository,
} from './profile-photo-view.repository';
import { PROFILE_PHOTO_VIEW_REPOSITORY } from './profile-photo-view.repository';

/**
 * Serving profile photos.
 *
 * Three surfaces, one rule: the stored status decides, and it is read again on
 * every request - never remembered from the link, a cache or the caller.
 *
 * - owner preview: the athlete may open their own photo while it is still
 *   PENDING or REJECTED, through a single-use link;
 * - staff preview: ADMIN/OWNER may open a PENDING or APPROVED photo through the
 *   same kind of link (the route adds step-up);
 * - public read: anyone may open an APPROVED photo, and nothing else.
 *
 * Every refusal is the same generic `NotFoundException`, so a caller cannot
 * tell a missing photo from a foreign one or from one that is not approved.
 * The links reuse the document primitives (signing, one-time nonce, sealed
 * envelope) under their own token purpose, so a document link can never be
 * replayed here.
 */

/** The accountable actions, as they appear in the audit chain. */
export const PROFILE_PHOTO_VIEW_ACTIONS = {
  LINK_ISSUED: 'profile.photo.view_link_issued',
  VIEWED: 'profile.photo.viewed',
} as const;

export type ProfilePhotoViewAction =
  (typeof PROFILE_PHOTO_VIEW_ACTIONS)[keyof typeof PROFILE_PHOTO_VIEW_ACTIONS];

/** Who a link was issued for; also what the trail calls the access. */
export type ProfilePhotoViewBasis = 'owner' | 'staff';

const AUDIT_TARGET_TYPE = 'profile_photo';
/** Written instead of a value that is not a known role. */
const UNKNOWN = 'unknown';
/** Domain separation: these links are not document links, by construction. */
const TOKEN_PURPOSE = 'profile-photo-view';

/** What the caller receives: a link, and how long it lives. No photo data. */
export interface ProfilePhotoPreviewLink {
  readonly token: string;
  readonly expiresInSeconds: number;
}

/** The plaintext a read yields, with what it was stored as. */
export interface ProfilePhotoBytes {
  readonly bytes: Buffer;
  readonly contentType: PhotoContentType;
  /** The length of the bytes actually returned, not the row's claim about them. */
  readonly sizeBytes: number;
}

/** One row of the public listing: metadata a stranger may see. */
export interface ApprovedPhotoView {
  readonly id: string;
  readonly caption: string | null;
  readonly contentType: PhotoContentType;
  readonly sizeBytes: number;
  readonly createdAt: string;
}

export interface ApprovedPhotoPage {
  readonly photos: ApprovedPhotoView[];
  /** The id to pass as `cursor` for the next page, or null at the end. */
  readonly nextCursor: string | null;
}

/** The page the public list asked for; the route already validated it. */
export interface PublicPhotoListRequest {
  readonly limit: number;
  readonly cursor?: string;
}

function notFound(): NotFoundException {
  // Generic on purpose: a foreign photo, a missing one and a non-approved one
  // answer exactly alike.
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

/**
 * The signing key for these links: derived from the document view secret, so
 * deployments need no extra variable and the two token families stay disjoint.
 */
function deriveSecret(base: string): string {
  return createHmac('sha256', base).update(TOKEN_PURPOSE, 'utf8').digest('hex');
}

/** The facts a redemption is decided on, read fresh from the database. */
export interface PhotoViewDecisionInput {
  /** The viewer as the database holds them now; null when the account is gone. */
  readonly viewer: { readonly id: string; readonly role: string; readonly status: string } | null;
  /** The photo and its owner as they are now; null when the row is gone. */
  readonly record: ProfilePhotoViewRecord | null;
  /** True when the link claims a staff preview. */
  readonly staff: boolean;
}

/**
 * The one rule that matters, as a pure function:
 *
 * - a link without a live viewer is refused;
 * - a staff link needs a current staff role and a photo that is not REJECTED
 *   (PENDING and APPROVED are exactly what review needs to see);
 * - an owner link needs the photo to still belong to the viewer, and allows any
 *   status, because the owner is previewing their own upload.
 *
 * The status is re-read here on purpose: approval is a state, not a one-time
 * event, and a photo rejected after a link was issued must stop opening.
 */
export function mayRedeemProfilePhotoView(input: PhotoViewDecisionInput): boolean {
  const { viewer, record, staff } = input;

  if (viewer === null || viewer.status !== 'ACTIVE') return false;

  const role = parseRole(viewer.role);

  if (role === null || record === null) return false;

  if (staff) return isStaffRole(role) && staffMayPreview(record.photo.status);

  return record.ownerUserId === viewer.id;
}

/**
 * What a staff link may open: a photo still under review or approved. A REJECTED
 * or REMOVED row is not previewable - a taken-down photo must not come back
 * through a link issued before the takedown.
 */
function staffMayPreview(status: ProfilePhotoStatus): boolean {
  return status === 'PENDING' || status === 'APPROVED';
}

@Injectable()
export class ProfilePhotoViewService {
  private readonly secret: string | undefined;

  constructor(
    @Inject(ENV) env: Pick<Env, 'DOCUMENT_VIEW_TOKEN_SECRET'>,
    @Inject(PROFILE_PHOTO_VIEW_REPOSITORY) private readonly photos: ProfilePhotoViewRepository,
    @Inject(SESSION_REPOSITORY) private readonly accounts: SessionRepository,
    // The same one-time store the OTP proof and document links use: SET NX to
    // remember, GETDEL to spend. Null when no shared store is configured, which
    // fails closed below.
    @Inject(PROOF_NONCE_STORE) private readonly nonces: ProofNonceStore | null,
    private readonly crypto: DocumentCryptoService,
    @Inject(DOCUMENT_STORAGE) private readonly storage: DocumentStorage,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {
    this.secret =
      env.DOCUMENT_VIEW_TOKEN_SECRET === undefined
        ? undefined
        : deriveSecret(env.DOCUMENT_VIEW_TOKEN_SECRET);
  }

  /**
   * A link the owner may use on their own photo, whatever its status.
   *
   * A foreign id and a missing id answer alike: neither the existence nor the
   * owner of a photo is disclosed.
   */
  async issueOwnerLink(
    actor: PolicySubject,
    photoId: string,
    nowMs: number = Date.now(),
  ): Promise<ProfilePhotoPreviewLink> {
    const record = await this.load(photoId);

    if (record === null || record.ownerUserId !== actor.id) throw notFound();

    return this.issue(actor, record.photo, 'owner', nowMs);
  }

  /**
   * A link a reviewer may use on a photo that is PENDING or APPROVED.
   *
   * The role is checked again here rather than trusted from the route: the rule
   * belongs with the decision, so a future caller cannot skip it.
   */
  async issueStaffLink(
    actor: PolicySubject,
    photoId: string,
    nowMs: number = Date.now(),
  ): Promise<ProfilePhotoPreviewLink> {
    const role = parseRole(String(actor.role));

    if (role === null || !isStaffRole(role)) throw notFound();

    const record = await this.load(photoId);

    if (record === null || !staffMayPreview(record.photo.status)) throw notFound();

    return this.issue(actor, record.photo, 'staff', nowMs);
  }

  /**
   * Spends one link and returns the photo's plaintext.
   *
   * Order: verify the token, spend the nonce, reload the photo and the viewer,
   * decide again, record the view, then read and decrypt. The second decision
   * is not a repeat of the first - a rejection, a role change, a block or a
   * deleted row since the issue is caught here.
   */
  async redeem(token: unknown, nowMs: number = Date.now()): Promise<ProfilePhotoBytes> {
    const secret = this.requireSecret();

    // 1. Signature and expiry only: a forged token must never spend a nonce.
    const payload = verifyViewToken({ secret, token, nowMs });

    if (payload === null) throw notFound();

    // 2. Single use: reading the nonce and deleting it are one step, so two
    //    simultaneous redemptions cannot both find it.
    let stored: string | null;

    try {
      stored = await this.requireNonces().take(payload.jti);
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'store' },
        'profile photo view link not spent',
      );
      throw unavailable();
    }

    if (stored === null || !sameValue(stored, payload.viewerUserId)) throw notFound();

    // 3. Fresh rows: the token names them, it does not describe them.
    const [record, viewer] = await Promise.all([
      this.load(payload.documentId),
      this.loadViewer(payload.viewerUserId),
    ]);

    if (!mayRedeemProfilePhotoView({ viewer, record, staff: payload.staff })) throw notFound();

    // The decision can only be allowed when both rows exist; this keeps the
    // types honest without adding a second rule.
    if (record === null || viewer === null) throw notFound();

    // 4. The trail comes before the bytes.
    await this.appendTrail(
      PROFILE_PHOTO_VIEW_ACTIONS.VIEWED,
      viewer.id,
      viewer.role,
      record.photo,
      payload.staff ? 'staff' : 'owner',
    );

    // 5 and 6. Read the blob, then open the envelope with its own object key.
    return this.unseal(record.photo, await this.read(record.photo));
  }

  /**
   * The public read: one APPROVED photo, and only that.
   *
   * The status is checked on this request's row, so revoking an approval closes
   * the photo immediately - no cached decision, no link involved.
   */
  async readApproved(photoId: string): Promise<ProfilePhotoBytes> {
    const record = await this.load(photoId);

    if (record === null || record.photo.status !== 'APPROVED') throw notFound();

    return this.unseal(record.photo, await this.read(record.photo));
  }

  /**
   * The public listing of one profile's approved photos.
   *
   * A page is read with one extra row to learn whether another page exists; the
   * extra row itself never leaves the service. A profile with nothing approved
   * (or no profile at all) answers with an empty page, so the route cannot be
   * used to probe which profiles exist.
   */
  async listApproved(
    athleteProfileId: string,
    request: PublicPhotoListRequest,
  ): Promise<ApprovedPhotoPage> {
    const rows = await this.listRows(athleteProfileId, request);

    const photos = rows.slice(0, request.limit).map(toApprovedView);
    const last = photos[photos.length - 1];

    return {
      photos,
      nextCursor: rows.length > request.limit && last !== undefined ? last.id : null,
    };
  }

  /** Loads one photo row; a lookup failure is a 503, never a 404. */
  private async load(photoId: string): Promise<ProfilePhotoViewRecord | null> {
    try {
      return await this.photos.findById(photoId);
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'photo' },
        'profile photo view lookup failed',
      );
      throw unavailable();
    }
  }

  /** The viewer as the database holds them right now, role and status included. */
  private async loadViewer(
    userId: string,
  ): Promise<{ id: string; role: string; status: string } | null> {
    try {
      const account = await this.accounts.findUserById(userId);

      return account === null
        ? null
        : { id: account.id, role: String(account.role), status: account.status };
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'viewer' },
        'profile photo view viewer lookup failed',
      );
      throw unavailable();
    }
  }

  /** One page plus the sentinel row; a lookup failure is a 503. */
  private async listRows(
    athleteProfileId: string,
    request: PublicPhotoListRequest,
  ): Promise<ApprovedPhotoSummary[]> {
    try {
      return await this.photos.listApproved(athleteProfileId, request.limit + 1, request.cursor);
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'list' },
        'profile photo listing failed',
      );
      throw unavailable();
    }
  }

  /** Reads the ciphertext; the object key is never logged, echoed or stored. */
  private async read(photo: ProfilePhotoRecord): Promise<Buffer> {
    try {
      return await this.storage.get(photo.objectKey);
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'storage' },
        'profile photo storage read failed',
      );
      throw unavailable();
    }
  }

  /** Opens the envelope; the object key is the AAD, so a moved blob fails here. */
  private async unseal(photo: ProfilePhotoRecord, ciphertext: Buffer): Promise<ProfilePhotoBytes> {
    let bytes: Buffer;

    try {
      bytes = await this.crypto.decrypt(
        {
          ciphertext,
          iv: photo.iv,
          authTag: photo.authTag,
          wrappedDek: photo.wrappedDek,
          keyId: photo.keyId,
        },
        photo.objectKey,
      );
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.VIEWED, stage: 'decrypt' },
        'profile photo decryption failed',
      );
      throw unavailable();
    }

    return { bytes, contentType: photo.contentType, sizeBytes: bytes.length };
  }

  /**
   * Mints a link for a photo the caller has already been allowed to see, and
   * remembers who it was minted for. Fail closed: a link nobody can account for
   * is never handed out.
   */
  private async issue(
    actor: PolicySubject,
    photo: ProfilePhotoRecord,
    basis: ProfilePhotoViewBasis,
    nowMs: number,
  ): Promise<ProfilePhotoPreviewLink> {
    const secret = this.requireSecret();
    const nonces = this.requireNonces();

    await this.appendTrail(
      PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
      actor.id,
      String(actor.role),
      photo,
      basis,
    );

    const issued = issueViewToken({
      secret,
      documentId: photo.id,
      viewerUserId: actor.id,
      staff: basis === 'staff',
      nowMs,
    });

    // The nonce remembers who it was minted for; redemption compares the two.
    try {
      if (!(await nonces.put(issued.jti, actor.id, VIEW_LINK_CONSUMPTION_TTL_SECONDS))) {
        throw new Error('view nonce collision');
      }
    } catch {
      this.logger.warn(
        { action: PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED, stage: 'store' },
        'profile photo view link not stored',
      );
      throw unavailable();
    }

    return { token: issued.token, expiresInSeconds: VIEW_LINK_TTL_SECONDS };
  }

  /**
   * Ids, a status and a basis only: the metadata can never carry the object
   * key, a hash, a caption or any of the bytes.
   */
  private async appendTrail(
    action: ProfilePhotoViewAction,
    actorId: string,
    role: string,
    photo: ProfilePhotoRecord,
    basis: ProfilePhotoViewBasis,
  ): Promise<void> {
    const viewerRole = parseRole(role) ?? UNKNOWN;

    try {
      await this.audit.record({
        action,
        actorId,
        actorRole: viewerRole,
        targetType: AUDIT_TARGET_TYPE,
        targetId: photo.id,
        metadata: {
          photoId: photo.id,
          athleteProfileId: photo.athleteProfileId,
          status: photo.status,
          viewerRole,
          accessBasis: basis,
        },
      });
    } catch {
      // Only the action and the stage are logged: no id, no key, no message from
      // the exception.
      this.logger.warn({ action, stage: 'audit' }, 'profile photo view not recorded');
      throw unavailable();
    }
  }

  /** A configured signing secret, or the feature is off (503). */
  private requireSecret(): string {
    if (this.secret === undefined) throw unavailable();

    return this.secret;
  }

  /** A configured one-time store, or the feature is off (503). */
  private requireNonces(): ProofNonceStore {
    if (this.nonces === null) throw unavailable();

    return this.nonces;
  }
}

/** The wire shape of a listing row; `createdAt` is serialised once, here. */
function toApprovedView(row: ApprovedPhotoSummary): ApprovedPhotoView {
  return {
    id: row.id,
    caption: row.caption,
    contentType: row.contentType,
    sizeBytes: row.sizeBytes,
    createdAt: row.createdAt.toISOString(),
  };
}
