import { HttpException, NotFoundException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import { InMemorySessionRepository } from '../../auth/in-memory-session.repository';
import type { ProofNonceStore } from '../../auth/proof/proof-nonce.store';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import type { Env } from '../../config/env';
import { DocumentCryptoService } from '../../documents/document-crypto.service';
import { EnvKeyWrapper } from '../../documents/env-key-wrapper';
import { InMemoryDocumentStorage } from '../../documents/in-memory-document-storage';
import { buildPng, TEXT_CHUNK } from '../../documents/ingest/testing/image-fixtures';
import { issueViewToken, VIEW_LINK_TTL_SECONDS } from '../../documents/view/view-token';
import type { ProfilePhotoRecord } from './profile-photo.repository';
import type {
  ApprovedPhotoSummary,
  ProfilePhotoViewRecord,
  ProfilePhotoViewRepository,
} from './profile-photo-view.repository';
import { PROFILE_PHOTO_VIEW_ACTIONS, ProfilePhotoViewService } from './profile-photo-view.service';

/**
 * `ProfilePhotoViewService`, driven directly: the crypto, the storage and the
 * session repository are the real in-memory ones, and every other seam is a
 * small recording stand-in.
 *
 * What this spec pins is the contract the routes sit on: only APPROVED photos
 * are public, a view link is spent exactly once and re-checks the viewer and
 * the photo when it is spent, every refusal is the same generic 404, every
 * infrastructure failure is a 503 with the object key still secret, and the
 * trail carries a row for both the issue and the view.
 */

/** Fixed, fake master key: base64 of exactly 32 bytes. */
const MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=';
/** The base document secret; the service derives its own key from it. */
const VIEW_SECRET = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC12aWV3LXNlY3JldA==';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_USER_ID = '44444444-4444-4444-8444-444444444444';
const STAFF_ID = '55555555-5555-4555-8555-555555555555';
const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_PROFILE_ID = '22222222-2222-4222-8222-222222222222';
const NOW = Date.parse('2026-01-01T00:00:00.000Z');
/** One second past the link's own lifetime. */
const AFTER_EXPIRY = NOW + (VIEW_LINK_TTL_SECONDS + 1) * 1_000;

const PNG = buildPng({ chunks: [TEXT_CHUNK] });

const owner: PolicySubject = { id: USER_ID, role: Role.ATHLETE };
const staff: PolicySubject = { id: STAFF_ID, role: Role.ADMIN };

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class QuietLogger {
  readonly warns: unknown[] = [];

  warn(payload: unknown): void {
    this.warns.push(payload);
  }
}

class RecordingAudit extends FakeAudit {
  fail = false;

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    if (this.fail) throw new Error('audit chain is unavailable');

    await super.record(entry, tx);
  }
}

class RecordingStorage extends InMemoryDocumentStorage {
  readonly gets: string[] = [];
  failGet = false;

  override async get(objectKey: string): Promise<Buffer> {
    this.gets.push(objectKey);

    if (this.failGet) throw new Error('storage is unavailable');

    return super.get(objectKey);
  }
}
/** Newest first; equal timestamps break the tie by descending id. */
function byNewestFirst(a: ProfilePhotoViewRecord, b: ProfilePhotoViewRecord): number {
  const delta = b.photo.createdAt.getTime() - a.photo.createdAt.getTime();

  if (delta !== 0) return delta;

  return a.photo.id < b.photo.id ? 1 : a.photo.id > b.photo.id ? -1 : 0;
}

/** The listing projection: metadata only, exactly like the SQL `select`. */
function toSummary(row: ProfilePhotoViewRecord): ApprovedPhotoSummary {
  return {
    id: row.photo.id,
    caption: row.photo.caption,
    contentType: row.photo.contentType,
    sizeBytes: row.photo.sizeBytes,
    createdAt: row.photo.createdAt,
  };
}

/** The read-only view repository: a map of rows with settable failures. */
class InMemoryViewPhotos implements ProfilePhotoViewRepository {
  readonly rows = new Map<string, ProfilePhotoViewRecord>();
  failFind = false;
  failList = false;

  async findById(photoId: string): Promise<ProfilePhotoViewRecord | null> {
    if (this.failFind) throw new Error('database is unavailable');

    return this.rows.get(photoId) ?? null;
  }

  async listApproved(
    athleteProfileId: string,
    limit: number,
    cursor?: string,
  ): Promise<ApprovedPhotoSummary[]> {
    if (this.failList) throw new Error('database is unavailable');

    const approved = [...this.rows.values()]
      .filter(
        (row) => row.photo.athleteProfileId === athleteProfileId && row.photo.status === 'APPROVED',
      )
      .sort(byNewestFirst);
    // An unknown cursor starts at the beginning, like the real keyset query.
    const start =
      cursor === undefined ? 0 : approved.findIndex((row) => row.photo.id === cursor) + 1;

    return approved.slice(start, start + limit).map(toSummary);
  }
}

/** The put/take contract of the Redis store, plus a switch for its failure. */
class InMemoryNonces implements ProofNonceStore {
  readonly entries = new Map<string, { subject: string; ttlSeconds: number }>();
  failTake = false;

  async put(jti: string, subject: string, ttlSeconds: number): Promise<boolean> {
    if (this.entries.has(jti)) return false;

    this.entries.set(jti, { subject, ttlSeconds });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    if (this.failTake) throw new Error('nonce store is unavailable');

    const entry = this.entries.get(jti);

    this.entries.delete(jti);

    return entry?.subject ?? null;
  }
}

const crypto = new DocumentCryptoService(new EnvKeyWrapper({ masterKey: MASTER_KEY }));

interface Seed {
  readonly photoId?: string;
  readonly ownerUserId?: string;
  readonly athleteProfileId?: string;
  readonly status?: ProfilePhotoRecord['status'];
  readonly createdAt?: Date;
}

/** Seals the fixture PNG under a fresh object key and registers the row. */
async function seed(
  photos: InMemoryViewPhotos,
  storage: RecordingStorage,
  overrides: Seed = {},
): Promise<ProfilePhotoViewRecord> {
  const photoId = overrides.photoId ?? randomUUID();
  const objectKey = `profile-photos/${photoId}`;
  const sealed = await crypto.encrypt(PNG, objectKey);
  const row: ProfilePhotoViewRecord = {
    ownerUserId: overrides.ownerUserId ?? USER_ID,
    photo: {
      id: photoId,
      athleteProfileId: overrides.athleteProfileId ?? PROFILE_ID,
      objectKey,
      caption: null,
      status: overrides.status ?? 'PENDING',
      contentType: 'image/png',
      sizeBytes: PNG.length,
      sha256: sha256(PNG),
      keyId: sealed.keyId,
      wrappedDek: sealed.wrappedDek,
      iv: sealed.iv,
      authTag: sealed.authTag,
      createdAt: overrides.createdAt ?? new Date(NOW),
      reviewedAt: null,
      reviewedById: null,
    },
  };

  photos.rows.set(photoId, row);
  await storage.put(objectKey, sealed.ciphertext);

  return row;
}
interface Harness {
  readonly service: ProfilePhotoViewService;
  readonly photos: InMemoryViewPhotos;
  readonly storage: RecordingStorage;
  readonly audit: RecordingAudit;
  readonly sessions: InMemorySessionRepository;
  readonly nonces: InMemoryNonces;
  readonly logger: QuietLogger;
}

/** A wired service over the in-memory seams; pass `null` to drop a dependency. */
function harness(
  overrides: { secret?: string | null; nonces?: ProofNonceStore | null } = {},
): Harness {
  const photos = new InMemoryViewPhotos();
  const storage = new RecordingStorage();
  const audit = new RecordingAudit();
  const sessions = new InMemorySessionRepository();
  const nonces = new InMemoryNonces();
  const injected = overrides.nonces === undefined ? nonces : overrides.nonces;
  const secret = overrides.secret === undefined ? VIEW_SECRET : overrides.secret;
  const logger = new QuietLogger();
  const env = secret === null ? {} : { DOCUMENT_VIEW_TOKEN_SECRET: secret };
  const service = new ProfilePhotoViewService(
    env as Pick<Env, 'DOCUMENT_VIEW_TOKEN_SECRET'>,
    photos,
    sessions,
    injected,
    crypto,
    storage,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  sessions.seedUser({
    id: USER_ID,
    phone: '+15005550001',
    username: 'owner',
    role: Role.ATHLETE,
    status: 'ACTIVE',
  });
  sessions.seedUser({
    id: STAFF_ID,
    phone: '+15005550002',
    username: 'staff',
    role: Role.ADMIN,
    status: 'ACTIVE',
  });

  return { service, photos, storage, audit, sessions, nonces, logger };
}

/** The message and status of whatever a call threw; fails when it threw nothing. */
async function refusal(run: () => Promise<unknown>): Promise<{ message: string; status: number }> {
  try {
    await run();
  } catch (error) {
    if (!(error instanceof Error)) throw error;

    return {
      message: error.message,
      status: error instanceof HttpException ? error.getStatus() : 0,
    };
  }

  throw new Error('the call was expected to refuse');
}

describe('ProfilePhotoViewService', () => {
  describe('reading an approved photo publicly', () => {
    it('serves the decrypted bytes with the stored type and their real length', async () => {
      const { service, photos, storage } = harness();
      const row = await seed(photos, storage, { status: 'APPROVED' });

      const served = await service.readApproved(row.photo.id);

      expect(served.bytes.equals(PNG)).toBe(true);
      expect(served.contentType).toBe('image/png');
      expect(served.sizeBytes).toBe(PNG.length);
      expect(served.sizeBytes).not.toBe(row.photo.sizeBytes + 1);
    });

    it('answers a PENDING, a REJECTED, a REMOVED and an unknown photo with the same generic 404', async () => {
      const { service, photos, storage } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const rejected = await seed(photos, storage, { status: 'REJECTED' });
      const removed = await seed(photos, storage, { status: 'REMOVED' });

      const answers = await Promise.all([
        refusal(() => service.readApproved(pending.photo.id)),
        refusal(() => service.readApproved(rejected.photo.id)),
        refusal(() => service.readApproved(removed.photo.id)),
        refusal(() => service.readApproved(randomUUID())),
      ]);

      expect(new Set(answers.map((answer) => answer.message)).size).toBe(1);
      expect(answers.every((answer) => answer.status === 404)).toBe(true);
    });

    it('stops serving a photo the moment its approval is withdrawn', async () => {
      const { service, photos, storage, audit } = harness();
      const approved = await seed(photos, storage, { status: 'APPROVED' });

      await expect(service.readApproved(approved.photo.id)).resolves.toBeDefined();

      // The next request reads the row again; a public read writes no trail.
      const rejectedAgain = await seed(photos, storage, {
        photoId: approved.photo.id,
        status: 'REJECTED',
      });

      await expect(service.readApproved(rejectedAgain.photo.id)).rejects.toBeInstanceOf(
        NotFoundException,
      );
      expect(audit.records).toHaveLength(0);
    });

    it('reports a storage failure as a 503 and never as a 404', async () => {
      const { service, photos, storage, logger } = harness();
      const approved = await seed(photos, storage, { status: 'APPROVED' });

      storage.failGet = true;

      const answer = await refusal(() => service.readApproved(approved.photo.id));

      expect(answer.status).toBe(503);
      expect(logger.warns).toHaveLength(1);
      expect(JSON.stringify(logger.warns)).not.toContain(approved.photo.objectKey);
    });

    it('reports a blob that no longer opens as a 503, not as a 404', async () => {
      const { service, photos, storage, logger } = harness();
      const approved = await seed(photos, storage, { status: 'APPROVED' });

      // A moved or truncated blob: the object key is the AAD, so it cannot open.
      await storage.put(approved.photo.objectKey, Buffer.alloc(16, 0));

      const answer = await refusal(() => service.readApproved(approved.photo.id));

      expect(answer.status).toBe(503);
      expect(logger.warns).toHaveLength(1);
    });
  });
  describe('owner preview links', () => {
    it('refuses a photo that belongs to someone else without writing anything', async () => {
      const { service, photos, storage, audit, nonces } = harness();
      const foreign = await seed(photos, storage, {
        status: 'APPROVED',
        ownerUserId: OTHER_USER_ID,
      });

      const answer = await refusal(() => service.issueOwnerLink(owner, foreign.photo.id, NOW));

      expect(answer.status).toBe(404);
      expect(audit.records).toHaveLength(0);
      expect(nonces.entries.size).toBe(0);
    });

    it('lets the owner preview their own PENDING upload and records the issue', async () => {
      const { service, photos, storage, audit } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });

      const link = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      expect(link.expiresInSeconds).toBe(VIEW_LINK_TTL_SECONDS);
      expect(typeof link.token).toBe('string');
      expect(audit.records).toHaveLength(1);
      expect(audit.records[0]).toMatchObject({
        action: PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
        actorId: USER_ID,
        actorRole: Role.ATHLETE,
        targetType: 'profile_photo',
        targetId: pending.photo.id,
      });
      expect(audit.records[0]?.metadata).toMatchObject({
        photoId: pending.photo.id,
        athleteProfileId: PROFILE_ID,
        status: 'PENDING',
        accessBasis: 'owner',
      });
    });

    it('spends a link exactly once and records the view before the bytes', async () => {
      const { service, photos, storage, audit, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      const served = await service.redeem(token, NOW);

      expect(served.bytes.equals(PNG)).toBe(true);
      expect(nonces.entries.size).toBe(0);
      expect(audit.records.map((row) => row.action)).toEqual([
        PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
        PROFILE_PHOTO_VIEW_ACTIONS.VIEWED,
      ]);
      expect(audit.records[1]?.metadata).toMatchObject({ accessBasis: 'owner' });

      const replay = await refusal(() => service.redeem(token, NOW));

      expect(replay.status).toBe(404);
      expect(audit.records).toHaveLength(2);
    });

    it('opens an own photo at any status, including after a rejection', async () => {
      const { service, photos, storage } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const first = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      await expect(service.redeem(first.token, NOW)).resolves.toBeDefined();

      // The same id, now rejected: the owner is previewing what they uploaded.
      const rejected = await seed(photos, storage, {
        photoId: pending.photo.id,
        status: 'REJECTED',
      });
      const second = await service.issueOwnerLink(owner, rejected.photo.id, NOW);

      await expect(service.redeem(second.token, NOW)).resolves.toBeDefined();
    });

    it('follows the row: a photo that changes hands before redemption is refused', async () => {
      const { service, photos, storage, sessions } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      sessions.seedUser({
        id: OTHER_USER_ID,
        phone: '+15005550003',
        username: 'other',
        role: Role.ATHLETE,
        status: 'ACTIVE',
      });
      photos.rows.set(pending.photo.id, { ...pending, ownerUserId: OTHER_USER_ID });

      const answer = await refusal(() => service.redeem(token, NOW));

      expect(answer.status).toBe(404);
    });

    it('refuses a link once the account is blocked', async () => {
      const { service, photos, storage, sessions } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      sessions.users.get(USER_ID)!.status = 'BLOCKED';

      const answer = await refusal(() => service.redeem(token, NOW));

      expect(answer.status).toBe(404);
    });

    it('refuses a link that has already expired, without spending its nonce', async () => {
      const { service, photos, storage, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      const answer = await refusal(() => service.redeem(token, AFTER_EXPIRY));

      expect(answer.status).toBe(404);
      expect(nonces.entries.size).toBe(1);
    });

    it('refuses a token minted for the document purpose', async () => {
      const { service, photos, storage, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'APPROVED' });
      // Signed with the base secret, not the derived profile-photo key.
      const forged = issueViewToken({
        secret: VIEW_SECRET,
        documentId: pending.photo.id,
        viewerUserId: USER_ID,
        staff: false,
        nowMs: NOW,
      });

      const answer = await refusal(() => service.redeem(forged.token, NOW));

      expect(answer.status).toBe(404);
      expect(nonces.entries.size).toBe(0);
    });
  });
  describe('staff preview links', () => {
    it('refuses a caller who is not staff, without writing anything', async () => {
      const { service, photos, storage, audit, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });

      const answer = await refusal(() => service.issueStaffLink(owner, pending.photo.id, NOW));

      expect(answer.status).toBe(404);
      expect(audit.records).toHaveLength(0);
      expect(nonces.entries.size).toBe(0);
    });

    it('opens a PENDING photo for a reviewer and records the basis', async () => {
      const { service, photos, storage, audit } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });

      const { token } = await service.issueStaffLink(staff, pending.photo.id, NOW);
      const served = await service.redeem(token, NOW);

      expect(served.bytes.equals(PNG)).toBe(true);
      expect(audit.records.map((row) => row.action)).toEqual([
        PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
        PROFILE_PHOTO_VIEW_ACTIONS.VIEWED,
      ]);
      expect(audit.records[0]).toMatchObject({ actorId: STAFF_ID, actorRole: Role.ADMIN });
      expect(audit.records[0]?.metadata).toMatchObject({ accessBasis: 'staff' });
    });

    it('refuses a REJECTED photo at issue', async () => {
      const { service, photos, storage, audit } = harness();
      const rejected = await seed(photos, storage, { status: 'REJECTED' });

      const answer = await refusal(() => service.issueStaffLink(staff, rejected.photo.id, NOW));

      expect(answer.status).toBe(404);
      expect(audit.records).toHaveLength(0);
    });

    it('stops opening a link when the photo is rejected before it is spent', async () => {
      const { service, photos, storage, audit } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueStaffLink(staff, pending.photo.id, NOW);

      await seed(photos, storage, { photoId: pending.photo.id, status: 'REJECTED' });

      const answer = await refusal(() => service.redeem(token, NOW));

      expect(answer.status).toBe(404);
      // Only the issue is on the trail: nothing was served.
      expect(audit.records.map((row) => row.action)).toEqual([
        PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
      ]);
    });

    it('stops opening a link once the reviewer loses the role', async () => {
      const { service, photos, storage, sessions, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueStaffLink(staff, pending.photo.id, NOW);

      sessions.setUserRole(STAFF_ID, { role: Role.ATHLETE });

      const answer = await refusal(() => service.redeem(token, NOW));

      expect(answer.status).toBe(404);
      // The nonce was spent before the role was read: the link is dead either way.
      expect(nonces.entries.size).toBe(0);
    });
  });

  describe('failing closed', () => {
    it('answers 503 on both surfaces when no signing secret is configured', async () => {
      const { service, photos, storage, audit } = harness({ secret: null });
      const approved = await seed(photos, storage, { status: 'APPROVED' });

      const issue = await refusal(() => service.issueOwnerLink(owner, approved.photo.id, NOW));
      const redeem = await refusal(() => service.redeem('any-token', NOW));

      expect(issue.status).toBe(503);
      expect(redeem.status).toBe(503);
      // The public read needs no link, so it keeps working.
      await expect(service.readApproved(approved.photo.id)).resolves.toBeDefined();
      expect(audit.records).toHaveLength(0);
    });

    it('answers 503 for a link when no one-time store is configured', async () => {
      const { service, photos, storage, audit } = harness({ nonces: null });
      const pending = await seed(photos, storage, { status: 'PENDING' });

      const answer = await refusal(() => service.issueOwnerLink(owner, pending.photo.id, NOW));

      expect(answer.status).toBe(503);
      expect(audit.records).toHaveLength(0);
    });

    it('answers 503 when the one-time store fails at redemption', async () => {
      const { service, photos, storage, audit, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });
      const { token } = await service.issueOwnerLink(owner, pending.photo.id, NOW);

      nonces.failTake = true;

      const answer = await refusal(() => service.redeem(token, NOW));

      expect(answer.status).toBe(503);
      expect(audit.records.map((row) => row.action)).toEqual([
        PROFILE_PHOTO_VIEW_ACTIONS.LINK_ISSUED,
      ]);
    });

    it('refuses to hand out a link the trail cannot account for', async () => {
      const { service, photos, storage, audit, nonces } = harness();
      const pending = await seed(photos, storage, { status: 'PENDING' });

      audit.fail = true;

      const answer = await refusal(() => service.issueOwnerLink(owner, pending.photo.id, NOW));

      expect(answer.status).toBe(503);
      expect(nonces.entries.size).toBe(0);
    });

    it('answers 503 when the photo lookup itself fails', async () => {
      const { service, photos } = harness();
      const approved = await seed(photos, new RecordingStorage(), { status: 'APPROVED' });

      photos.failFind = true;

      const issue = await refusal(() => service.issueOwnerLink(owner, approved.photo.id, NOW));
      const read = await refusal(() => service.readApproved(approved.photo.id));

      expect(issue.status).toBe(503);
      expect(read.status).toBe(503);
    });
  });
  describe('the public listing', () => {
    it('lists only approved photos, newest first, and never the extra sentinel row', async () => {
      const { service, photos, storage } = harness();
      const oldest = await seed(photos, storage, {
        status: 'APPROVED',
        createdAt: new Date(NOW - 3_000),
      });
      const newest = await seed(photos, storage, {
        status: 'APPROVED',
        createdAt: new Date(NOW - 1_000),
      });
      const middle = await seed(photos, storage, {
        status: 'APPROVED',
        createdAt: new Date(NOW - 2_000),
      });

      await seed(photos, storage, { status: 'PENDING' });
      await seed(photos, storage, { status: 'REJECTED' });
      await seed(photos, storage, { status: 'APPROVED', athleteProfileId: OTHER_PROFILE_ID });

      const page = await service.listApproved(PROFILE_ID, { limit: 2 });

      expect(page.photos.map((photo) => photo.id)).toEqual([newest.photo.id, middle.photo.id]);
      expect(page.nextCursor).toBe(middle.photo.id);
      expect(page.photos.map((photo) => photo.id)).not.toContain(oldest.photo.id);
    });

    it('resumes from the cursor and ends with a null cursor', async () => {
      const { service, photos, storage } = harness();
      const first = await seed(photos, storage, {
        status: 'APPROVED',
        createdAt: new Date(NOW - 1_000),
      });
      const last = await seed(photos, storage, {
        status: 'APPROVED',
        createdAt: new Date(NOW - 2_000),
      });

      const page = await service.listApproved(PROFILE_ID, { limit: 2, cursor: first.photo.id });

      expect(page.photos.map((photo) => photo.id)).toEqual([last.photo.id]);
      expect(page.nextCursor).toBeNull();
    });

    it('serves the first page for an unknown cursor instead of failing', async () => {
      const { service, photos, storage } = harness();
      const only = await seed(photos, storage, { status: 'APPROVED' });

      const page = await service.listApproved(PROFILE_ID, { limit: 5, cursor: randomUUID() });

      expect(page.photos.map((photo) => photo.id)).toEqual([only.photo.id]);
      expect(page.nextCursor).toBeNull();
    });

    it('carries metadata only: no object key, no digest, no envelope', async () => {
      const { service, photos, storage } = harness();
      const approved = await seed(photos, storage, { status: 'APPROVED' });

      const page = await service.listApproved(PROFILE_ID, { limit: 20 });
      const [photo] = page.photos;

      expect(photo).toBeDefined();
      expect(Object.keys(photo!).sort()).toEqual([
        'caption',
        'contentType',
        'createdAt',
        'id',
        'sizeBytes',
      ]);
      expect(photo?.createdAt).toBe(new Date(NOW).toISOString());

      const wire = JSON.stringify(page);

      expect(wire).not.toContain(approved.photo.objectKey);
      expect(wire).not.toContain(approved.photo.sha256);
      expect(wire).not.toContain(approved.photo.wrappedDek.toString('base64'));
    });

    it('answers an empty page for a profile with nothing approved', async () => {
      const { service, photos, storage } = harness();
      await seed(photos, storage, { status: 'PENDING' });

      await expect(service.listApproved(OTHER_PROFILE_ID, { limit: 20 })).resolves.toEqual({
        photos: [],
        nextCursor: null,
      });
    });

    it('answers 503 when the listing query fails', async () => {
      const { service, photos } = harness();
      photos.failList = true;

      const answer = await refusal(() => service.listApproved(PROFILE_ID, { limit: 20 }));

      expect(answer.status).toBe(503);
    });
  });
});
