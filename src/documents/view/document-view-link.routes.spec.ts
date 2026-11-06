import type { HttpException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type { PinoLogger } from 'nestjs-pino';
import {
  FakeAudit,
  FakeLogger,
  type AuditRecord,
} from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import type { AuthenticatedRequest } from '../../auth/guards/auth.guard';
import { InMemorySessionRepository } from '../../auth/in-memory-session.repository';
import type { ProofNonceStore } from '../../auth/otp/proof-token';
import { Role } from '../../auth/roles';
import type { RateLimitDecision, RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentCryptoService } from '../document-crypto.service';
import { EnvKeyWrapper } from '../env-key-wrapper';
import { InMemoryDocumentStorage } from '../in-memory-document-storage';
import type { IdentityDocumentRecord } from '../records/identity-document.repository';
import { InMemoryIdentityDocuments } from '../records/testing/in-memory-identity-documents';
import { DocumentViewLinkController } from './document-view-link.controller';
import type { DocumentViewLink } from './document-view.service';
import { DOCUMENT_VIEW_ACTIONS, DocumentViewService } from './document-view.service';
import { StaffDocumentViewLinkController } from './staff-document-view-link.controller';
import { verifyViewToken } from './view-token';

/**
 * The two routes end to end, over the real `DocumentViewService`.
 *
 * Nothing here replaces the service: the point of this spec is what a caller
 * actually receives - a signed token, one audit row, and the same generic answer
 * for a document that is missing and one that belongs to somebody else.
 */

/** A fixed, fake 32-byte master key, built rather than spelled out. */
const MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
/** Fixed, fake view-token secret: a fixture, never a real value. */
const SECRET = 'test-only-view-token-secret-0123456789abcdef';
const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const STAFF_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = 'request-1';
const PLAINTEXT = Buffer.from('test-only identity document bytes', 'utf8');
const SHA256 = createHash('sha256').update(PLAINTEXT).digest('hex');

/** The same two operations the OTP proof store has: SET NX and GETDEL. */
class RecordingNonces implements ProofNonceStore {
  readonly entries = new Map<string, string>();
  readonly puts: { jti: string; value: string; ttlSeconds: number }[] = [];

  async put(jti: string, value: string, ttlSeconds: number): Promise<boolean> {
    if (this.entries.has(jti)) return false;

    this.entries.set(jti, value);
    this.puts.push({ jti, value, ttlSeconds });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const value = this.entries.get(jti) ?? null;

    this.entries.delete(jti);

    return value;
  }
}

/** The real in-memory store, plus the list of blobs the route asked for. */
class RecordingStorage extends InMemoryDocumentStorage {
  readonly reads: string[] = [];

  override async get(objectKey: string): Promise<Buffer> {
    this.reads.push(objectKey);

    return super.get(objectKey);
  }
}

/** Allows everything: this spec is about the routes, not about the budget. */
class AllowingRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 1, retryAfterSeconds: 0 };
  }
}

class FakeResponse {
  readonly headers = new Map<string, string>();

  setHeader(name: string, value: string): this {
    this.headers.set(name, value);

    return this;
  }

  status(): this {
    return this;
  }
}

interface Harness {
  readonly ownerRoute: DocumentViewLinkController;
  readonly staffRoute: StaffDocumentViewLinkController;
  readonly documents: InMemoryIdentityDocuments;
  readonly nonces: RecordingNonces;
  readonly storage: RecordingStorage;
  readonly audit: FakeAudit;
  readonly document: IdentityDocumentRecord;
}

interface HarnessOptions {
  /** Leaves the variable unset, so the feature has to fail closed. */
  readonly withoutSecret?: boolean;
  /** No shared store, as in a deployment that never configured Redis. */
  readonly withoutStore?: boolean;
}

/** One stored document, one account per role, and every seam real. */
async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const documents = new InMemoryIdentityDocuments();
  const sessions = new InMemorySessionRepository();
  const nonces = new RecordingNonces();
  const storage = new RecordingStorage();
  const audit = new FakeAudit();
  const crypto = new DocumentCryptoService(new EnvKeyWrapper({ masterKey: MASTER_KEY }));

  sessions.seedUser({ id: OWNER_ID, phone: '+14155550100', username: 'owner', role: Role.ATHLETE });
  sessions.seedUser({ id: STAFF_ID, phone: '+14155550101', username: 'staff', role: Role.ADMIN });
  sessions.seedUser({ id: USER_ID, phone: '+14155550102', username: 'other', role: Role.USER });

  const objectKey = randomUUID();
  const sealed = await crypto.encrypt(PLAINTEXT, objectKey);

  const document = await documents.insert({
    ownerUserId: OWNER_ID,
    kind: 'NATIONAL_ID',
    objectKey,
    contentType: 'image/png',
    sizeBytes: PLAINTEXT.length,
    sha256: SHA256,
    keyId: sealed.keyId,
    wrappedDek: sealed.wrappedDek,
    iv: sealed.iv,
    authTag: sealed.authTag,
  });

  const service = new DocumentViewService(
    { DOCUMENT_VIEW_TOKEN_SECRET: options.withoutSecret === true ? undefined : SECRET },
    documents,
    sessions,
    options.withoutStore === true ? null : nonces,
    crypto,
    storage,
    audit as unknown as AuditService,
    new FakeLogger() as unknown as PinoLogger,
  );

  const rateLimit = new AllowingRateLimit() as unknown as RateLimitService;

  return {
    ownerRoute: new DocumentViewLinkController(service, rateLimit),
    staffRoute: new StaffDocumentViewLinkController(service, rateLimit),
    documents,
    nonces,
    storage,
    audit,
    document,
  };
}

function request(userId: string, role: Role): AuthenticatedRequest {
  return {
    auth: { userId, sessionId: 'session-1', role, identityVerifier: false, expiresAtSeconds: 0 },
    headers: {},
    id: REQUEST_ID,
  } as unknown as AuthenticatedRequest;
}

/** The error a call threw, so its class and message can be compared. */
async function rejection(promise: Promise<unknown>): Promise<HttpException> {
  try {
    await promise;
  } catch (error) {
    return error as HttpException;
  }

  throw new Error('expected the call to fail');
}

function actionsOf(audit: FakeAudit): string[] {
  return audit.records.map((record) => record.action);
}

function lastRecord(audit: FakeAudit): AuditRecord {
  const entry = audit.records[audit.records.length - 1];

  if (entry === undefined) throw new Error('no audit record was written');

  return entry;
}

/** The owner route, called the way the framework would call it. */
async function issueOwn(
  harness: Harness,
  userId: string,
  role: Role,
  documentId: string,
): Promise<DocumentViewLink> {
  const body = await harness.ownerRoute.issueOwnLink(
    { documentId },
    request(userId, role),
    new FakeResponse() as unknown as Response,
  );

  return body as DocumentViewLink;
}

/** The staff route, called after its guards would have allowed it. */
async function issueAsStaff(
  harness: Harness,
  userId: string,
  role: Role,
  documentId: string,
): Promise<DocumentViewLink> {
  const body = await harness.staffRoute.issueLink(
    { documentId },
    request(userId, role),
    new FakeResponse() as unknown as Response,
  );

  return body as DocumentViewLink;
}

describe('the document view-link routes', () => {
  describe('the owner route', () => {
    it('issues a link the owner can spend, and records the issue first', async () => {
      const harness = await createHarness();

      const link = await issueOwn(harness, OWNER_ID, Role.ATHLETE, harness.document.id);

      expect(Object.keys(link).sort()).toEqual(['expiresInSeconds', 'token']);
      expect(link.expiresInSeconds).toBe(60);

      const payload = verifyViewToken({ secret: SECRET, token: link.token, nowMs: Date.now() });

      expect(payload).not.toBeNull();
      expect(payload?.documentId).toBe(harness.document.id);
      expect(payload?.viewerUserId).toBe(OWNER_ID);
      // The owner route never produces the staff basis.
      expect(payload?.staff).toBe(false);

      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.LINK_ISSUED]);
      expect(lastRecord(harness.audit)).toMatchObject({
        action: DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
        actorId: OWNER_ID,
        targetType: 'identity_document',
        targetId: harness.document.id,
        metadata: { accessBasis: 'owner', documentId: harness.document.id, kind: 'NATIONAL_ID' },
      });
      // One nonce, kept a little longer than the link itself.
      expect(harness.nonces.puts).toHaveLength(1);
      expect(harness.nonces.puts[0]?.value).toBe(OWNER_ID);
      expect(harness.nonces.puts[0]?.ttlSeconds).toBe(120);
      // Issuing a link reads no bytes: the blob is served elsewhere.
      expect(harness.storage.reads).toEqual([]);
    });

    it('answers a foreign document and a missing one identically', async () => {
      const harness = await createHarness();

      const foreign = await rejection(issueOwn(harness, USER_ID, Role.USER, harness.document.id));
      const foreignAudit = lastRecord(harness.audit);

      const missing = await rejection(issueOwn(harness, USER_ID, Role.USER, randomUUID()));
      const missingAudit = lastRecord(harness.audit);

      // Same status and same generic message: the response cannot say whether
      // the row exists.
      expect(foreign.getStatus()).toBe(404);
      expect(missing.getStatus()).toBe(404);
      expect(foreign.message).toBe('Not Found');
      expect(missing.message).toBe(foreign.message);

      // And the same trail: no document id, no target, no reason on the row.
      expect(actionsOf(harness.audit)).toEqual([
        DOCUMENT_VIEW_ACTIONS.DENIED,
        DOCUMENT_VIEW_ACTIONS.DENIED,
      ]);
      expect(missingAudit).toEqual(foreignAudit);
      expect('targetId' in foreignAudit).toBe(false);
      expect(harness.nonces.puts).toEqual([]);
    });

    it('refuses a staff caller who did not use the staff route', async () => {
      const harness = await createHarness();

      // StaffGate and the step-up belong to the staff route; the owner route is
      // not a second way to read somebody else's document.
      const error = await rejection(issueOwn(harness, STAFF_ID, Role.ADMIN, harness.document.id));

      expect(error.getStatus()).toBe(404);
      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.DENIED]);
      expect(harness.nonces.puts).toEqual([]);
    });

    it('lets a staff caller read their own document on the owner basis', async () => {
      const harness = await createHarness();
      const own = await harness.documents.insert({
        ownerUserId: STAFF_ID,
        kind: 'CERTIFICATE',
        objectKey: randomUUID(),
        contentType: 'image/png',
        sizeBytes: PLAINTEXT.length,
        sha256: SHA256,
        keyId: 'v1',
        wrappedDek: Buffer.alloc(61, 1),
        iv: Buffer.alloc(12, 2),
        authTag: Buffer.alloc(16, 3),
      });

      const link = await issueOwn(harness, STAFF_ID, Role.ADMIN, own.id);
      const payload = verifyViewToken({ secret: SECRET, token: link.token, nowMs: Date.now() });

      expect(payload?.staff).toBe(false);
      expect(lastRecord(harness.audit).metadata).toMatchObject({ accessBasis: 'owner' });
    });
  });

  describe('the staff route', () => {
    it.each([Role.ADMIN, Role.OWNER])(
      'issues a staff-basis link for an %s session',
      async (role) => {
        const harness = await createHarness();

        const link = await issueAsStaff(harness, STAFF_ID, role, harness.document.id);
        const payload = verifyViewToken({ secret: SECRET, token: link.token, nowMs: Date.now() });

        expect(payload?.staff).toBe(true);
        expect(payload?.documentId).toBe(harness.document.id);
        expect(payload?.viewerUserId).toBe(STAFF_ID);
        expect(lastRecord(harness.audit)).toMatchObject({
          action: DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
          actorId: STAFF_ID,
          targetId: harness.document.id,
          metadata: { accessBasis: 'staff', viewerRole: role },
        });
        // Still no bytes: the issue route only decides and signs.
        expect(harness.storage.reads).toEqual([]);
      },
    );

    it('answers a missing document with the same generic 404 as the owner route', async () => {
      const harness = await createHarness();

      const staffError = await rejection(issueAsStaff(harness, STAFF_ID, Role.ADMIN, randomUUID()));
      const ownerError = await rejection(issueOwn(harness, USER_ID, Role.USER, randomUUID()));

      expect(staffError.getStatus()).toBe(404);
      expect(staffError.message).toBe(ownerError.message);
      expect(staffError.message).toBe('Not Found');
      expect(harness.nonces.puts).toEqual([]);
    });

    it('records a denial without a target, exactly like the owner route', async () => {
      const harness = await createHarness();

      await rejection(issueAsStaff(harness, USER_ID, Role.USER, randomUUID()));

      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.DENIED]);
      expect('targetId' in lastRecord(harness.audit)).toBe(false);
    });
  });

  describe('a deployment that cannot issue a link', () => {
    it('answers one generic 503 without the signing secret', async () => {
      const harness = await createHarness({ withoutSecret: true });

      for (const call of [
        issueOwn(harness, OWNER_ID, Role.ATHLETE, harness.document.id),
        issueAsStaff(harness, STAFF_ID, Role.ADMIN, harness.document.id),
      ]) {
        const error = await rejection(call);

        expect(error.getStatus()).toBe(503);
        expect(error.message).toBe('Service Unavailable');
      }

      expect(harness.audit.records).toEqual([]);
      expect(harness.nonces.puts).toEqual([]);
      expect(harness.storage.reads).toEqual([]);
    });

    it('answers the same 503 without the one-time store', async () => {
      const harness = await createHarness({ withoutStore: true });

      for (const call of [
        issueOwn(harness, OWNER_ID, Role.ATHLETE, harness.document.id),
        issueAsStaff(harness, STAFF_ID, Role.ADMIN, harness.document.id),
      ]) {
        const error = await rejection(call);

        expect(error.getStatus()).toBe(503);
        expect(error.message).toBe('Service Unavailable');
      }

      expect(harness.audit.records).toEqual([]);
      expect(harness.storage.reads).toEqual([]);
    });
  });
});
