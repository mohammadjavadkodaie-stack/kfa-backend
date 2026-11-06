import type { HttpException } from '@nestjs/common';
import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { createHash, randomUUID } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import {
  FakeAudit,
  FakeLogger,
  type AuditRecord,
} from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import { InMemorySessionRepository } from '../../auth/in-memory-session.repository';
import type { ProofNonceStore } from '../../auth/otp/proof-token';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import { DocumentCryptoService, type EncryptedDocument } from '../document-crypto.service';
import { EnvKeyWrapper } from '../env-key-wrapper';
import { InMemoryDocumentStorage } from '../in-memory-document-storage';
import type { IdentityDocumentRecord } from '../records/identity-document.repository';
import { InMemoryIdentityDocuments } from '../records/testing/in-memory-identity-documents';
import { DOCUMENT_VIEW_ACTIONS, DocumentViewService } from './document-view.service';
import { issueViewToken } from './view-token';

/**
 * A fixed, fake 32-byte master key, built rather than spelled out: the document
 * layer only needs *a* key here, and a computed value keeps the secret scanners
 * as quiet as the fixtures in the other document specs.
 */
const MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
/** Fixed, fake view-token secret: a fixture, never a real value. */
const SECRET = 'test-only-view-token-secret-0123456789abcdef';
const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const STAFF_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '33333333-3333-4333-8333-333333333333';
/** 2026-03-01T00:00:00.000Z, the only clock the specs use. */
const NOW_MS = Date.UTC(2026, 2, 1, 0, 0, 0);
const PLAINTEXT = Buffer.from('test-only identity document bytes', 'utf8');
const SHA256 = createHash('sha256').update(PLAINTEXT).digest('hex');

const ownerSubject: PolicySubject = { id: OWNER_ID, role: Role.ATHLETE };
const staffSubject: PolicySubject = { id: STAFF_ID, role: Role.ADMIN };
const userSubject: PolicySubject = { id: USER_ID, role: Role.USER };

/** The order the steps ran in, shared by every fake in one test. */
class Timeline {
  readonly events: string[] = [];

  mark(event: string): void {
    this.events.push(event);
  }

  reset(): void {
    this.events.length = 0;
  }
}

class RecordingDocuments extends InMemoryIdentityDocuments {
  failRead = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async findActiveById(
    id: string,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null> {
    this.timeline.mark('document');

    if (this.failRead) throw new Error('database is unavailable');

    return super.findActiveById(id, tx);
  }
}

class RecordingSessions extends InMemorySessionRepository {
  failRead = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async findUserById(userId: string) {
    this.timeline.mark('viewer');

    if (this.failRead) throw new Error('database is unavailable');

    return super.findUserById(userId);
  }
}

/** The same two operations the OTP proof store has: SET NX and GETDEL. */
class RecordingNonces implements ProofNonceStore {
  readonly entries = new Map<string, string>();
  readonly puts: { jti: string; value: string; ttlSeconds: number }[] = [];
  failPut = false;
  failTake = false;

  constructor(private readonly timeline: Timeline) {}

  async put(jti: string, value: string, ttlSeconds: number): Promise<boolean> {
    this.timeline.mark('issue-store');

    if (this.failPut) throw new Error('redis is unavailable');
    if (this.entries.has(jti)) return false;

    this.entries.set(jti, value);
    this.puts.push({ jti, value, ttlSeconds });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    this.timeline.mark('store');

    if (this.failTake) throw new Error('redis is unavailable');

    const value = this.entries.get(jti) ?? null;

    this.entries.delete(jti);

    return value;
  }

  get size(): number {
    return this.entries.size;
  }
}

class RecordingStorage extends InMemoryDocumentStorage {
  readonly reads: string[] = [];
  readonly writes: string[] = [];
  failGet = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.writes.push(objectKey);

    return super.put(objectKey, bytes);
  }

  override async get(objectKey: string): Promise<Buffer> {
    this.timeline.mark('storage');
    this.reads.push(objectKey);

    if (this.failGet) throw new Error('document not found');

    return super.get(objectKey);
  }
}

class RecordingCrypto extends DocumentCryptoService {
  readonly aads: string[] = [];
  failDecrypt = false;

  constructor(private readonly timeline: Timeline) {
    super(new EnvKeyWrapper({ masterKey: MASTER_KEY }));
  }

  override async decrypt(document: EncryptedDocument, aad: string): Promise<Buffer> {
    this.timeline.mark('decrypt');
    this.aads.push(aad);

    if (this.failDecrypt) throw new Error('document unreadable');

    return super.decrypt(document, aad);
  }
}

class RecordingAudit extends FakeAudit {
  failNext = false;

  constructor(private readonly timeline: Timeline) {
    super();
  }

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    this.timeline.mark('audit');

    if (this.failNext) throw new Error('audit chain is unavailable');

    await super.record(entry, tx);
  }
}

interface Harness {
  readonly service: DocumentViewService;
  readonly documents: RecordingDocuments;
  readonly sessions: RecordingSessions;
  readonly nonces: RecordingNonces;
  readonly storage: RecordingStorage;
  readonly crypto: RecordingCrypto;
  readonly audit: RecordingAudit;
  readonly logger: FakeLogger;
  readonly timeline: Timeline;
  readonly document: IdentityDocumentRecord;
  readonly objectKey: string;
}

interface HarnessOptions {
  /** Leaves the variable unset, so the feature has to fail closed. */
  readonly withoutSecret?: boolean;
  /** No shared store, as in a deployment that never configured Redis. */
  readonly withoutStore?: boolean;
}

/**
 * One seeded document, one seeded account per role, and every collaborator
 * recording what it was asked to do.
 */
async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const timeline = new Timeline();
  const documents = new RecordingDocuments(timeline);
  const sessions = new RecordingSessions(timeline);
  const nonces = new RecordingNonces(timeline);
  const storage = new RecordingStorage(timeline);
  const crypto = new RecordingCrypto(timeline);
  const audit = new RecordingAudit(timeline);
  const logger = new FakeLogger();

  sessions.seedUser({ id: OWNER_ID, phone: '+14155550100', username: 'owner', role: Role.ATHLETE });
  sessions.seedUser({ id: STAFF_ID, phone: '+14155550101', username: 'staff', role: Role.ADMIN });
  sessions.seedUser({ id: USER_ID, phone: '+14155550102', username: 'other', role: Role.USER });

  const objectKey = randomUUID();
  const sealed = await crypto.encrypt(PLAINTEXT, objectKey);

  await storage.put(objectKey, sealed.ciphertext);

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
    logger as unknown as PinoLogger,
  );

  // Seeding is not part of any expectation.
  timeline.reset();

  return {
    service,
    documents,
    sessions,
    nonces,
    storage,
    crypto,
    audit,
    logger,
    timeline,
    document,
    objectKey,
  };
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

function recordOf(audit: FakeAudit, action: string): AuditRecord {
  const entry = audit.records.find((record) => record.action === action);

  if (entry === undefined) throw new Error(`no audit record for ${action}`);

  return entry;
}

/** A signed token this service never issued, for tokens with a chosen payload. */
function forgeToken(documentId: string, viewerUserId: string, staff: boolean) {
  return issueViewToken({ secret: SECRET, documentId, viewerUserId, staff, nowMs: NOW_MS });
}

describe('DocumentViewService', () => {
  describe('the owner reading their own document', () => {
    it('issues a link and yields the plaintext once', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect(Object.keys(link).sort()).toEqual(['expiresInSeconds', 'token']);
      expect(link.expiresInSeconds).toBe(60);

      const view = await harness.service.redeem(link.token, NOW_MS);

      expect(Object.keys(view).sort()).toEqual(['bytes', 'contentType', 'sizeBytes']);
      expect(view.bytes.equals(PLAINTEXT)).toBe(true);
      expect(view.contentType).toBe('image/png');
      expect(view.sizeBytes).toBe(PLAINTEXT.length);
    });

    it('records the issue and the read, on the owner basis', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      await harness.service.redeem(link.token, NOW_MS);

      expect(actionsOf(harness.audit)).toEqual([
        DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
        DOCUMENT_VIEW_ACTIONS.VIEWED,
      ]);

      const issued = recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.LINK_ISSUED);

      expect(issued.actorId).toBe(OWNER_ID);
      expect(issued.actorRole).toBe(Role.ATHLETE);
      expect(issued.targetType).toBe('identity_document');
      expect(issued.targetId).toBe(harness.document.id);
      expect(issued.metadata).toEqual({
        documentId: harness.document.id,
        kind: 'NATIONAL_ID',
        viewerRole: Role.ATHLETE,
        accessBasis: 'owner',
      });
      expect(recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.VIEWED).metadata).toEqual(
        issued.metadata,
      );
    });

    it('keeps the nonce longer than the link it belongs to', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect(harness.nonces.puts).toHaveLength(1);
      expect(harness.nonces.puts[0]?.ttlSeconds).toBeGreaterThan(link.expiresInSeconds);
      // The nonce remembers the viewer, not the document: redemption compares it.
      expect(harness.nonces.puts[0]?.value).toBe(OWNER_ID);
    });

    it('reads the document before it writes the trail, and decrypts last', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect(harness.timeline.events).toEqual(['document', 'audit', 'issue-store']);

      harness.timeline.reset();

      await harness.service.redeem(link.token, NOW_MS);

      expect(harness.timeline.events).toEqual([
        'store',
        'document',
        'viewer',
        'audit',
        'storage',
        'decrypt',
      ]);
    });

    it('opens the envelope with its own object key', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      await harness.service.redeem(link.token, NOW_MS);

      expect(harness.storage.reads).toEqual([harness.objectKey]);
      expect(harness.crypto.aads).toEqual([harness.objectKey]);
    });
  });

  describe('staff reading a foreign document', () => {
    it('allows it only with an explicit step-up, on the staff basis', async () => {
      const harness = await createHarness();

      const link = await harness.service.issueLink(
        staffSubject,
        { documentId: harness.document.id, staffVerified: true },
        NOW_MS,
      );

      const view = await harness.service.redeem(link.token, NOW_MS);

      expect(view.bytes.equals(PLAINTEXT)).toBe(true);
      expect(recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.VIEWED).metadata).toMatchObject({
        accessBasis: 'staff',
        viewerRole: Role.ADMIN,
      });
    });

    it('refuses it when the caller did not assert the step-up', async () => {
      const harness = await createHarness();

      const error = await rejection(
        harness.service.issueLink(staffSubject, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.nonces.size).toBe(0);
      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.DENIED]);
    });

    it('refuses it when the step-up was asserted as false', async () => {
      const harness = await createHarness();

      const error = await rejection(
        harness.service.issueLink(
          staffSubject,
          { documentId: harness.document.id, staffVerified: false },
          NOW_MS,
        ),
      );

      expect(error).toBeInstanceOf(NotFoundException);
    });

    it('never widens a regular account, whatever the flag says', async () => {
      const harness = await createHarness();

      const error = await rejection(
        harness.service.issueLink(
          userSubject,
          { documentId: harness.document.id, staffVerified: true },
          NOW_MS,
        ),
      );

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
    });
  });

  describe('every refusal looks the same', () => {
    it('answers a foreign document exactly like a missing one', async () => {
      const foreign = await createHarness();
      const missing = await createHarness();

      const foreignError = await rejection(
        foreign.service.issueLink(userSubject, { documentId: foreign.document.id }, NOW_MS),
      );
      const missingError = await rejection(
        missing.service.issueLink(userSubject, { documentId: randomUUID() }, NOW_MS),
      );

      expect(foreignError).toBeInstanceOf(NotFoundException);
      expect(missingError).toBeInstanceOf(NotFoundException);
      expect(foreignError.constructor).toBe(missingError.constructor);
      expect(foreignError.getStatus()).toBe(404);
      expect(foreignError.message).toBe(missingError.message);
      // The trace cannot tell the two apart either: same action, no target.
      expect(missing.audit.records).toHaveLength(1);

      const denied = missing.audit.records[0] as AuditRecord;

      expect(denied.action).toBe(DOCUMENT_VIEW_ACTIONS.DENIED);
      expect(denied.actorId).toBe(USER_ID);
      expect((denied as { targetId?: string }).targetId).toBeUndefined();
      expect(denied.metadata).toEqual({ actorRole: Role.USER, action: 'document.view' });
      // Nothing was read, stored or handed out.
      expect(foreign.nonces.size).toBe(0);
      expect(foreign.storage.reads).toEqual([]);
    });

    it('refuses a soft-deleted document to its own owner', async () => {
      const harness = await createHarness();

      harness.documents.softDelete(harness.document.id);

      const error = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(NotFoundException);
      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.DENIED]);
    });

    it('refuses an unknown role rather than guessing one', async () => {
      const harness = await createHarness();
      const ghost = { id: OWNER_ID, role: 'SUPERUSER' as Role };

      const error = await rejection(
        harness.service.issueLink(ghost, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(NotFoundException);
      expect(recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.DENIED).metadata).toEqual({
        actorRole: 'unknown',
        action: 'document.view',
      });
    });

    it('still refuses when the denial cannot be recorded', async () => {
      const harness = await createHarness();

      harness.audit.failNext = true;

      const error = await rejection(
        harness.service.issueLink(userSubject, { documentId: harness.document.id }, NOW_MS),
      );

      // A refusal is best effort: the caller learns nothing either way.
      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.audit.records).toEqual([]);
      expect(harness.logger.warns).toHaveLength(2);
    });
  });

  describe('spending a link exactly once', () => {
    it('refuses a replay', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect((await harness.service.redeem(link.token, NOW_MS)).sizeBytes).toBe(PLAINTEXT.length);

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      // Exactly one read was recorded, and the blob was read only once.
      expect(actionsOf(harness.audit)).toEqual([
        DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
        DOCUMENT_VIEW_ACTIONS.VIEWED,
      ]);
      expect(harness.storage.reads).toHaveLength(1);
    });

    it('lets only one of two simultaneous redemptions win', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      const results = await Promise.allSettled([
        harness.service.redeem(link.token, NOW_MS),
        harness.service.redeem(link.token, NOW_MS),
      ]);

      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
      expect(harness.storage.reads).toHaveLength(1);
    });

    it('does not burn the nonce on a tampered token', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );
      const tampered = `${link.token.slice(0, -1)}${link.token.endsWith('A') ? 'B' : 'A'}`;

      const error = await rejection(harness.service.redeem(tampered, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      // The real link still works, so the forgery spent nothing.
      expect(harness.nonces.size).toBe(1);
      expect((await harness.service.redeem(link.token, NOW_MS)).sizeBytes).toBe(PLAINTEXT.length);
    });

    it('does not burn the nonce on an expired token', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      const error = await rejection(harness.service.redeem(link.token, NOW_MS + 60_000));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.nonces.size).toBe(1);
      expect((await harness.service.redeem(link.token, NOW_MS + 59_000)).sizeBytes).toBe(
        PLAINTEXT.length,
      );
    });

    it('refuses a token that is not one of ours, without touching the store', async () => {
      const harness = await createHarness();

      for (const token of ['', 'not-a-token', 'a.b', 'x'.repeat(4_096), undefined]) {
        const error = await rejection(harness.service.redeem(token, NOW_MS));

        expect(error).toBeInstanceOf(NotFoundException);
      }

      expect(harness.timeline.events).toEqual([]);
      expect(harness.audit.records).toEqual([]);
    });

    it('refuses a token whose nonce is gone', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.nonces.entries.clear();

      expect(await rejection(harness.service.redeem(link.token, NOW_MS))).toBeInstanceOf(
        NotFoundException,
      );
    });

    it('refuses a nonce minted for another viewer', async () => {
      const harness = await createHarness();
      const forged = forgeToken(harness.document.id, OWNER_ID, false);

      // The signature is genuine, but the stored subject is somebody else.
      harness.nonces.entries.set(forged.jti, USER_ID);

      const error = await rejection(harness.service.redeem(forged.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
    });
  });

  describe('re-deciding against fresh rows', () => {
    it('refuses a link after the staff account lost its role', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        staffSubject,
        { documentId: harness.document.id, staffVerified: true },
        NOW_MS,
      );

      expect(await harness.sessions.setRoleIf(STAFF_ID, Role.ADMIN, Role.USER)).toBe(true);

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
      expect(recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.DENIED).metadata).toMatchObject({
        actorRole: Role.USER,
      });
    });

    it('refuses a link after the owner was blocked', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect(await harness.sessions.setStatusIf(OWNER_ID, 'ACTIVE', 'BLOCKED')).toBe(true);

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
      expect(harness.crypto.aads).toEqual([]);
    });

    it('refuses a link after the document was soft-deleted', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.documents.softDelete(harness.document.id);

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
    });

    it('refuses a link after the viewer row is gone', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.sessions.users.delete(OWNER_ID);

      expect(await rejection(harness.service.redeem(link.token, NOW_MS))).toBeInstanceOf(
        NotFoundException,
      );
      expect(recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.DENIED).metadata).toMatchObject({
        actorRole: 'unknown',
      });
    });

    it('trusts the rows, not the token, when the document never existed', async () => {
      const harness = await createHarness();
      const forged = forgeToken(randomUUID(), OWNER_ID, false);

      // Even a nonce that exists cannot make a missing row viewable.
      expect(await harness.nonces.put(forged.jti, OWNER_ID, 120)).toBe(true);

      const error = await rejection(harness.service.redeem(forged.token, NOW_MS));

      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
      expect(
        (recordOf(harness.audit, DOCUMENT_VIEW_ACTIONS.DENIED) as { targetId?: string }).targetId,
      ).toBeUndefined();
    });

    it('keeps a link that was issued without a step-up at that level', async () => {
      const harness = await createHarness();
      const forged = forgeToken(harness.document.id, STAFF_ID, false);

      expect(await harness.nonces.put(forged.jti, STAFF_ID, 120)).toBe(true);

      const error = await rejection(harness.service.redeem(forged.token, NOW_MS));

      // The token records what was decided; it cannot widen it on the way back.
      expect(error).toBeInstanceOf(NotFoundException);
      expect(harness.storage.reads).toEqual([]);
    });
  });

  describe('failing closed', () => {
    it('turns the feature off without a secret', async () => {
      const harness = await createHarness({ withoutSecret: true });

      const issueError = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );
      const redeemError = await rejection(harness.service.redeem('a.b', NOW_MS));

      expect(issueError).toBeInstanceOf(ServiceUnavailableException);
      expect(redeemError).toBeInstanceOf(ServiceUnavailableException);
      expect(issueError.getStatus()).toBe(503);
      expect(harness.audit.records).toEqual([]);
      expect(harness.timeline.events).toEqual([]);
    });

    it('turns the feature off without a shared one-time store', async () => {
      const harness = await createHarness({ withoutStore: true });

      const issueError = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );
      const redeemError = await rejection(harness.service.redeem('a.b', NOW_MS));

      // No store means no single use, so there is no degraded mode to fall back to.
      expect(issueError).toBeInstanceOf(ServiceUnavailableException);
      expect(redeemError).toBeInstanceOf(ServiceUnavailableException);
      expect(harness.audit.records).toEqual([]);
      expect(harness.storage.reads).toEqual([]);
    });

    it('returns no link when the nonce cannot be stored', async () => {
      const harness = await createHarness();

      harness.nonces.failPut = true;

      const error = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      // The issue row stands: it describes what was decided, and no link was given.
      expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.LINK_ISSUED]);
      expect(harness.storage.reads).toEqual([]);
    });

    it('returns no bytes when the nonce cannot be spent', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.timeline.reset();
      harness.nonces.failTake = true;

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(harness.timeline.events).toEqual(['store']);
      expect(harness.storage.reads).toEqual([]);
    });

    it('gives out no link when the issue cannot be recorded', async () => {
      const harness = await createHarness();

      harness.audit.failNext = true;

      const error = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(harness.nonces.size).toBe(0);
      expect(harness.storage.reads).toEqual([]);
    });

    it('reads nothing when the view cannot be recorded', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.audit.failNext = true;

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      // The trail comes before the bytes: neither the read nor the decrypt ran.
      expect(harness.storage.reads).toEqual([]);
      expect(harness.crypto.aads).toEqual([]);
    });

    it('reports a failed document lookup as unavailable, not as missing', async () => {
      const harness = await createHarness();

      harness.documents.failRead = true;

      const error = await rejection(
        harness.service.issueLink(ownerSubject, { documentId: harness.document.id }, NOW_MS),
      );

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      expect(harness.audit.records).toEqual([]);
    });

    it('reports a failed viewer lookup as unavailable', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.sessions.failRead = true;

      expect(await rejection(harness.service.redeem(link.token, NOW_MS))).toBeInstanceOf(
        ServiceUnavailableException,
      );
      expect(harness.storage.reads).toEqual([]);
    });

    it('returns no bytes when the blob cannot be read', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.storage.failGet = true;

      const error = await rejection(harness.service.redeem(link.token, NOW_MS));

      expect(error).toBeInstanceOf(ServiceUnavailableException);
      // The read was already accounted for, so it is not repeated quietly.
      expect(actionsOf(harness.audit)).toEqual([
        DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
        DOCUMENT_VIEW_ACTIONS.VIEWED,
      ]);
      expect(harness.crypto.aads).toEqual([]);
    });

    it('returns no bytes when the envelope does not open', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      harness.crypto.failDecrypt = true;

      expect(await rejection(harness.service.redeem(link.token, NOW_MS))).toBeInstanceOf(
        ServiceUnavailableException,
      );
    });

    it('refuses a blob that was moved under another object key', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      // Same row, somebody else's ciphertext: the object key is the AAD, so GCM
      // refuses it instead of handing back the wrong document.
      const other = await harness.crypto.encrypt(
        Buffer.from('test-only other bytes', 'utf8'),
        randomUUID(),
      );

      await harness.storage.put(harness.objectKey, other.ciphertext);

      expect(await rejection(harness.service.redeem(link.token, NOW_MS))).toBeInstanceOf(
        ServiceUnavailableException,
      );
    });
  });

  describe('what leaves the service', () => {
    it('hands out a token that carries nothing but its claims', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      expect(link.token).not.toContain(harness.objectKey);
      expect(link.token).not.toContain(SHA256);
      expect(link.token).not.toContain('test-only identity document bytes');
      expect(link.token).not.toContain('.png');
      expect(link.token).not.toContain(OWNER_ID);
    });

    it('records no key, hash or byte in the trail', async () => {
      const harness = await createHarness();
      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      await harness.service.redeem(link.token, NOW_MS);

      const trail = JSON.stringify(harness.audit.records);

      expect(trail).not.toContain(harness.objectKey);
      expect(trail).not.toContain(SHA256);
      expect(trail).not.toContain('identity document bytes');
      expect(harness.audit.records.map((record) => Object.keys(record.metadata).sort())).toEqual([
        ['accessBasis', 'documentId', 'kind', 'viewerRole'],
        ['accessBasis', 'documentId', 'kind', 'viewerRole'],
      ]);
    });

    it('logs no id, key or byte, whatever fails', async () => {
      const harness = await createHarness();

      harness.storage.failGet = true;
      harness.crypto.failDecrypt = true;

      const link = await harness.service.issueLink(
        ownerSubject,
        { documentId: harness.document.id },
        NOW_MS,
      );

      await rejection(harness.service.redeem(link.token, NOW_MS));

      const logs = JSON.stringify(harness.logger.warns);

      expect(logs).not.toContain(harness.objectKey);
      expect(logs).not.toContain(harness.document.id);
      expect(logs).not.toContain(OWNER_ID);
      expect(logs).not.toContain(SHA256);
      // What is left is the action and the stage, which is the whole point.
      expect(logs).toContain('document.viewed');
      expect(logs).toContain('storage');
    });
  });
});
