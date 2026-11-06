import type { HttpException } from '@nestjs/common';
import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type { PinoLogger } from 'nestjs-pino';
import {
  FakeAudit,
  FakeLogger,
  type AuditRecord,
} from '../../../test/helpers/auth-service-harness';
import { TEST_ENV } from '../../../test/helpers/test-env';
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
import { issueViewToken, VIEW_LINK_TTL_SECONDS } from './view-token';

/**
 * The whole trip a single-use link makes: issued by the owner route, then spent
 * by `redeem()`.
 *
 * The service and the owner route are the real ones; only the seams below the
 * service - the document and session repositories, the object store, the
 * one-time nonce store, the audit chain and the clock - are in-memory fakes, and
 * they live in this file. Nothing here is wired into the application: production
 * keeps its Prisma, S3, Redis and audit implementations.
 *
 * The signing secret is the shared `test-only` fixture from `test-env`, so this
 * spec also proves that fixture is a working 32+ character HMAC key.
 */

/** The single, fixed, fake secret every suite signs a view link with. */
const SECRET = TEST_ENV.DOCUMENT_VIEW_TOKEN_SECRET;
/** A fixed, fake 32-byte master key, built rather than spelled out. */
const MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '33333333-3333-4333-8333-333333333333';
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

  get size(): number {
    return this.entries.size;
  }
}

/** What the trail looked like, read only by the fake storage below. */
interface AuditTrail {
  readonly records: readonly AuditRecord[];
}

/**
 * The real in-memory blob store, plus the list of keys it was asked for and a
 * snapshot of the audit trail taken at the instant of each read. The snapshot is
 * what proves the row exists before any byte leaves.
 */
class RecordingStorage extends InMemoryDocumentStorage {
  readonly reads: string[] = [];
  auditAtRead: string[] | null = null;

  constructor(private readonly trail: AuditTrail) {
    super();
  }

  override async get(objectKey: string): Promise<Buffer> {
    this.reads.push(objectKey);
    this.auditAtRead = this.trail.records.map((record) => record.action);

    return super.get(objectKey);
  }
}

/** The real audit stand-in, able to fail on demand; nothing else changes. */
class FailingAudit extends FakeAudit {
  failNext = false;

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    if (this.failNext) throw new Error('audit chain is unavailable');

    await super.record(entry, tx);
  }
}

/** Allows everything: this spec is about one redemption, not about the budget. */
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
  readonly route: DocumentViewLinkController;
  readonly service: DocumentViewService;
  readonly nonces: RecordingNonces;
  readonly storage: RecordingStorage;
  readonly audit: FailingAudit;
  readonly document: IdentityDocumentRecord;
  readonly objectKey: string;
}

/** One sealed document, one owner account and one stranger, all in memory. */
async function createHarness(): Promise<Harness> {
  const documents = new InMemoryIdentityDocuments();
  const sessions = new InMemorySessionRepository();
  const nonces = new RecordingNonces();
  const audit = new FailingAudit();
  const storage = new RecordingStorage(audit);
  const crypto = new DocumentCryptoService(new EnvKeyWrapper({ masterKey: MASTER_KEY }));

  sessions.seedUser({ id: OWNER_ID, phone: '+14155550100', username: 'owner', role: Role.ATHLETE });
  sessions.seedUser({ id: OTHER_ID, phone: '+14155550102', username: 'other', role: Role.USER });

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
    { DOCUMENT_VIEW_TOKEN_SECRET: SECRET },
    documents,
    sessions,
    nonces,
    crypto,
    storage,
    audit as unknown as AuditService,
    new FakeLogger() as unknown as PinoLogger,
  );

  const rateLimit = new AllowingRateLimit() as unknown as RateLimitService;

  return {
    route: new DocumentViewLinkController(service, rateLimit),
    service,
    nonces,
    storage,
    audit,
    document,
    objectKey,
  };
}

/** The principal the global guards would have attached to this request. */
function request(userId: string, role: Role): AuthenticatedRequest {
  return {
    auth: { userId, sessionId: 'session-1', role, identityVerifier: false, expiresAtSeconds: 0 },
    headers: {},
    id: REQUEST_ID,
  } as unknown as AuthenticatedRequest;
}

/** The owner route, called the way the framework would call it. */
async function issueOwn(
  harness: Harness,
  userId: string,
  documentId: string,
): Promise<DocumentViewLink> {
  const body = await harness.route.issueOwnLink(
    { documentId },
    request(userId, Role.ATHLETE),
    new FakeResponse() as unknown as Response,
  );

  return body as DocumentViewLink;
}

/** The error a call threw, so its class and status can be compared. */
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

describe('redeeming an owner view-link', () => {
  it('signs with the shared test-only fixture, not with another secret', () => {
    expect(SECRET).toContain('test-only');
    expect(SECRET).not.toBe(TEST_ENV.ACCESS_TOKEN_SECRET);
    expect(SECRET.length).toBeGreaterThanOrEqual(32);
  });

  it('returns the decrypted bytes and the contentType the row carries', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);
    const view = await harness.service.redeem(link.token);

    // The bytes are the plaintext that was sealed, opened with the row's own key.
    expect(view.bytes.equals(PLAINTEXT)).toBe(true);
    expect(view.contentType).toBe(harness.document.contentType);
    expect(view.contentType).toBe('image/png');
    expect(view.sizeBytes).toBe(PLAINTEXT.length);
    // One blob, read once, under the key the row names.
    expect(harness.storage.reads).toEqual([harness.objectKey]);
    expect(actionsOf(harness.audit)).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
  });

  it('refuses the same token a second time', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);

    expect((await harness.service.redeem(link.token)).sizeBytes).toBe(PLAINTEXT.length);

    const error = await rejection(harness.service.redeem(link.token));

    expect(error).toBeInstanceOf(NotFoundException);
    expect(error.getStatus()).toBe(404);
    // The replay never reached the blob, and it wrote no second view row.
    expect(harness.storage.reads).toHaveLength(1);
    expect(actionsOf(harness.audit)).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
  });

  it('refuses an expired token without spending its nonce', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);
    const afterExpiry = Date.now() + VIEW_LINK_TTL_SECONDS * 1_000;

    const error = await rejection(harness.service.redeem(link.token, afterExpiry));

    expect(error).toBeInstanceOf(NotFoundException);
    // Expiry is a signed claim, so the refusal costs nothing: the nonce is intact
    // and the still-live link keeps working.
    expect(harness.nonces.size).toBe(1);
    expect(harness.storage.reads).toEqual([]);
    expect((await harness.service.redeem(link.token)).sizeBytes).toBe(PLAINTEXT.length);
  });

  it('refuses a tampered token', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);
    // The first character of the payload segment, which the signature covers.
    const tampered = `${link.token.startsWith('A') ? 'B' : 'A'}${link.token.slice(1)}`;

    const error = await rejection(harness.service.redeem(tampered));

    expect(error).toBeInstanceOf(NotFoundException);
    expect(harness.storage.reads).toEqual([]);
    // The genuine link is untouched by the forgery.
    expect(harness.nonces.size).toBe(1);
  });

  it('refuses a token minted for another viewer than the stored one', async () => {
    const harness = await createHarness();
    // A genuine signature over the stranger's id - that account's link - while the
    // store remembers the owner for the very same nonce. Redemption compares the
    // two, so the mismatch is a refusal.
    const foreign = issueViewToken({
      secret: SECRET,
      documentId: harness.document.id,
      viewerUserId: OTHER_ID,
      staff: false,
      nowMs: Date.now(),
    });

    expect(await harness.nonces.put(foreign.jti, OWNER_ID, 120)).toBe(true);

    const error = await rejection(harness.service.redeem(foreign.token));

    expect(error).toBeInstanceOf(NotFoundException);
    expect(harness.storage.reads).toEqual([]);
    expect(harness.storage.auditAtRead).toBeNull();
  });

  it('writes the view row before it reads a single byte', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);

    await harness.service.redeem(link.token);

    // Taken inside the blob read: both rows, the issue and the view, were already
    // in the trail when the ciphertext was fetched.
    expect(harness.storage.auditAtRead).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
  });

  it('returns no bytes when the view cannot be recorded', async () => {
    const harness = await createHarness();

    const link = await issueOwn(harness, OWNER_ID, harness.document.id);

    harness.audit.failNext = true;

    const error = await rejection(harness.service.redeem(link.token));

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expect(error.getStatus()).toBe(503);
    // An access nobody could account for is refused, not served.
    expect(harness.storage.reads).toEqual([]);
    expect(harness.storage.auditAtRead).toBeNull();
    expect(actionsOf(harness.audit)).toEqual([DOCUMENT_VIEW_ACTIONS.LINK_ISSUED]);
  });
});
