import {
  NotFoundException,
  ServiceUnavailableException,
  type ArgumentsHost,
  type HttpException,
} from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import { VIEWED_FILE_ROUTE_PATTERN } from '../../logging/request-path';
import { TEST_ENV } from '../../../test/helpers/test-env';
import type { AuditService } from '../../audit/audit.service';
import { InMemorySessionRepository } from '../../auth/in-memory-session.repository';
import type { ProofNonceStore } from '../../auth/otp/proof-token';
import { Role } from '../../auth/roles';
import { AllExceptionsFilter } from '../../common/filters/all-exceptions.filter';
import type { RateLimitDecision, RateLimitService } from '../../rate-limit/rate-limit.service';
import { DocumentCryptoService } from '../document-crypto.service';
import { EnvKeyWrapper } from '../env-key-wrapper';
import { InMemoryDocumentStorage } from '../in-memory-document-storage';
import type { IdentityDocumentRecord } from '../records/identity-document.repository';
import { InMemoryIdentityDocuments } from '../records/testing/in-memory-identity-documents';
import { DocumentViewFileController } from './document-view-file.controller';
import { DOCUMENT_VIEW_ACTIONS, DocumentViewService } from './document-view.service';
import { issueViewToken, VIEW_LINK_TTL_SECONDS } from './view-token';

/**
 * `GET /documents/view/:token` end to end, below the framework.
 *
 * The route, the service and the exception filter are the real ones; only the
 * seams under the service are in-memory fakes - the document and session
 * repositories, the object store, the one-time nonce store and the trail - and
 * the response is recorded instead of sent. That is enough to prove the two
 * things this route must get right: a valid link yields exactly the stored
 * bytes with headers no cache or browser may reinterpret, and every refusal
 * looks the same and contains no byte of the document.
 */

/** The single, fixed, fake secret every suite signs a view link with. */
const SECRET = TEST_ENV.DOCUMENT_VIEW_TOKEN_SECRET;
/** A fixed, fake 32-byte master key, built rather than spelled out. */
const MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
const OWNER_ID = '11111111-1111-4111-8111-111111111111';
const STAFF_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_ID = '33333333-3333-4333-8333-333333333333';
const REQUEST_ID = 'request-1';
const IP = '203.0.113.9';
const PLAINTEXT = Buffer.from('test-only identity document bytes', 'utf8');
const SHA256 = createHash('sha256').update(PLAINTEXT).digest('hex');

/** The same two operations the OTP proof store has: SET NX and GETDEL. */
class RecordingNonces implements ProofNonceStore {
  readonly entries = new Map<string, string>();

  async put(jti: string, value: string, _ttlSeconds: number): Promise<boolean> {
    if (this.entries.has(jti)) return false;

    this.entries.set(jti, value);

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const value = this.entries.get(jti) ?? null;

    this.entries.delete(jti);

    return value;
  }
}

/** The trail stand-in, able to fail on demand. */
class FailingAudit extends FakeAudit {
  failNext = false;

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    if (this.failNext) throw new Error('audit chain is unavailable');

    await super.record(entry, tx);
  }
}

/** The real in-memory blob store, plus the keys it was asked for and a switch. */
class RecordingStorage extends InMemoryDocumentStorage {
  readonly reads: string[] = [];
  /** The trail as it looked at the instant of the last read. */
  auditAtRead: string[] | null = null;
  failNext = false;

  constructor(private readonly trail: { readonly records: readonly AuditRecord[] }) {
    super();
  }

  override async get(objectKey: string): Promise<Buffer> {
    this.reads.push(objectKey);
    this.auditAtRead = this.trail.records.map((record) => record.action);

    if (this.failNext) throw new Error('object store is unavailable');

    return super.get(objectKey);
  }
}

/** Allows everything: the budget has its own spec. */
class AllowingRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 1, retryAfterSeconds: 0 };
  }
}

/** Records what the route and the filter logged, without a pino instance. */
class RecordingLogger {
  readonly warns: unknown[][] = [];
  readonly errors: unknown[][] = [];

  info(): void {
    // Nothing the route does on the happy path is logged at info.
  }

  warn(...args: unknown[]): void {
    this.warns.push(args);
  }

  error(...args: unknown[]): void {
    this.errors.push(args);
  }
}

/** The response surface the controller and the filter use, recorded. */
class RecordingResponse {
  readonly headers = new Map<string, string>();
  statusCode = 200;
  /** The buffer of a success, or the envelope of a failure. */
  body: unknown = undefined;
  headersSent = false;

  setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  json(payload: unknown): this {
    this.body = payload;
    this.headersSent = true;
    return this;
  }

  /** One buffer, never a stream: the whole document or nothing. */
  end(chunk?: unknown): this {
    this.body = chunk;
    this.headersSent = true;
    return this;
  }
}

interface HarnessOptions {
  /** Models a deployment with no signing secret. */
  readonly withoutSecret?: boolean;
  /** Models a deployment with no shared one-time store. */
  readonly withoutStore?: boolean;
}

interface Harness {
  readonly route: DocumentViewFileController;
  readonly service: DocumentViewService;
  readonly nonces: RecordingNonces;
  readonly storage: RecordingStorage;
  readonly audit: FailingAudit;
  readonly logger: RecordingLogger;
  readonly filter: AllExceptionsFilter;
  readonly document: IdentityDocumentRecord;
}

/** One sealed document, one owner, one staff account and one stranger. */
async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const documents = new InMemoryIdentityDocuments();
  const sessions = new InMemorySessionRepository();
  const nonces = new RecordingNonces();
  const audit = new FailingAudit();
  const storage = new RecordingStorage(audit);
  const logger = new RecordingLogger();
  const crypto = new DocumentCryptoService(new EnvKeyWrapper({ masterKey: MASTER_KEY }));

  sessions.seedUser({ id: OWNER_ID, phone: '+14155550100', username: 'owner', role: Role.ATHLETE });
  sessions.seedUser({ id: STAFF_ID, phone: '+14155550101', username: 'staff', role: Role.ADMIN });
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
    { DOCUMENT_VIEW_TOKEN_SECRET: options.withoutSecret === true ? undefined : SECRET },
    documents,
    sessions,
    options.withoutStore === true ? null : nonces,
    crypto,
    storage,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return {
    route: new DocumentViewFileController(
      service,
      new AllowingRateLimit() as unknown as RateLimitService,
    ),
    service,
    nonces,
    storage,
    audit,
    logger,
    filter: new AllExceptionsFilter(logger as unknown as PinoLogger),
    document,
  };
}

/** The subject the global guards would have resolved for the issuer. */
function owner(): { id: string; role: Role } {
  return { id: OWNER_ID, role: Role.ATHLETE };
}

/** The subject of a staff link, which needs a step-up in the real request. */
function staff(): { id: string; role: Role } {
  return { id: STAFF_ID, role: Role.ADMIN };
}

/** A request shaped like the one the route receives, path token included. */
function createRequest(token: string): Request {
  return {
    id: REQUEST_ID,
    method: 'GET',
    ip: IP,
    headers: {},
    socket: { remoteAddress: IP },
    originalUrl: `/documents/view/${token}`,
    url: `/documents/view/${token}`,
  } as unknown as Request;
}

function createHost(request: Request, response: RecordingResponse): ArgumentsHost {
  return {
    switchToHttp: () => ({
      getResponse: () => response,
      getRequest: () => request,
    }),
  } as unknown as ArgumentsHost;
}

interface CallResult {
  readonly response: RecordingResponse;
  readonly error: HttpException | null;
}

/**
 * One call of the route, with a failure rendered by the real filter - the same
 * pair the application uses, so the body and the headers here are the ones a
 * client would actually receive.
 */
async function view(harness: Harness, token: string): Promise<CallResult> {
  const request = createRequest(token);
  const response = new RecordingResponse();

  try {
    await harness.route.view(token, request, response as unknown as Response);
  } catch (error) {
    harness.filter.catch(error, createHost(request, response));

    return { response, error: error as HttpException };
  }

  return { response, error: null };
}

/** A signed link this store never issued, with its nonce already in place. */
async function sealedToken(
  harness: Harness,
  input: {
    readonly documentId?: string;
    readonly viewerUserId?: string;
    readonly staff?: boolean;
    readonly nowMs?: number;
  } = {},
): Promise<string> {
  const issued = issueViewToken({
    secret: SECRET,
    documentId: input.documentId ?? harness.document.id,
    viewerUserId: input.viewerUserId ?? OWNER_ID,
    staff: input.staff ?? false,
    nowMs: input.nowMs ?? Date.now(),
  });

  await harness.nonces.put(issued.jti, input.viewerUserId ?? OWNER_ID, 120);

  return issued.token;
}

function actionsOf(audit: FakeAudit): string[] {
  return audit.records.map((record) => record.action);
}

/** The headers every answer of this route carries, refusals included. */
const PRIVATE_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['cache-control', 'no-store'],
  ['pragma', 'no-cache'],
  ['x-content-type-options', 'nosniff'],
  ['content-disposition', 'inline'],
  ['referrer-policy', 'no-referrer'],
  ['content-security-policy', "default-src 'none'; sandbox"],
  ['cross-origin-resource-policy', 'same-site'],
];

/** The seven headers every answer of this route carries, refusals included. */
function expectPrivateHeaders(response: RecordingResponse): void {
  for (const [name, value] of PRIVATE_HEADERS) {
    expect(response.headers.get(name)).toBe(value);
  }
}

/** The refusal shape: a status, the generic envelope, and not one byte. */
function expectRefusal(response: RecordingResponse, statusCode: number): void {
  expect(response.statusCode).toBe(statusCode);
  expectPrivateHeaders(response);
  expect(response.headers.has('content-type')).toBe(false);
  expect(response.headers.has('content-length')).toBe(false);
  expect(Buffer.isBuffer(response.body)).toBe(false);
  expect(response.body).toMatchObject({ statusCode, requestId: REQUEST_ID });
}

describe('serving the bytes behind a view link', () => {
  it('answers a valid owner link with the decrypted document and private headers', async () => {
    const harness = await createHarness();

    const link = await harness.service.issueLink(owner(), { documentId: harness.document.id });
    const { response, error } = await view(harness, link.token);

    expect(error).toBeNull();
    expect(response.statusCode).toBe(200);
    // Exactly the plaintext that was sealed: the envelope was opened with the
    // row's own key, and nothing was re-encoded on the way out.
    expect(Buffer.isBuffer(response.body)).toBe(true);
    expect(response.body).toEqual(PLAINTEXT);
    expect(response.headers.get('content-type')).toBe('image/png');
    expect(response.headers.get('content-length')).toBe(String(PLAINTEXT.length));
    expectPrivateHeaders(response);
  });

  it('serves a staff link the same way, and the trail keeps the staff actor', async () => {
    const harness = await createHarness();

    const link = await harness.service.issueLink(staff(), {
      documentId: harness.document.id,
      staffVerified: true,
    });
    const { response, error } = await view(harness, link.token);

    expect(error).toBeNull();
    expect(response.body).toEqual(PLAINTEXT);
    expect(actionsOf(harness.audit)).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
    expect(harness.audit.records.every((record) => record.actorRole === Role.ADMIN)).toBe(true);
  });

  it('writes the trail before it reads a single byte', async () => {
    const harness = await createHarness();
    const link = await harness.service.issueLink(owner(), { documentId: harness.document.id });

    await view(harness, link.token);

    // The snapshot the store took at the moment of the read: the view row was
    // already there, so no byte can leave before the trail accounts for it.
    expect(harness.storage.auditAtRead).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
    expect(harness.storage.reads).toHaveLength(1);
  });
});

describe('refusing a view link without a byte', () => {
  it('answers a replay, an expiry, a forgery, a stranger and a missing row alike', async () => {
    const harness = await createHarness();
    const link = await harness.service.issueLink(owner(), { documentId: harness.document.id });

    const served = await view(harness, link.token);
    expect(served.response.statusCode).toBe(200);

    const refusals = [
      // Spent: the nonce is gone, so the link never yields a second copy.
      await view(harness, link.token),
      // Expired: the clock inside the token is past the TTL.
      await view(
        harness,
        await sealedToken(harness, { nowMs: Date.now() - (VIEW_LINK_TTL_SECONDS + 60) * 1000 }),
      ),
      // Forged: one character of the signature changed.
      await view(harness, `${link.token.slice(0, -1)}${link.token.endsWith('A') ? 'B' : 'A'}`),
      // Signed for another account that is not the owner of this document.
      await view(harness, await sealedToken(harness, { viewerUserId: OTHER_ID })),
      // Signed for a document id this deployment does not hold.
      await view(harness, await sealedToken(harness, { documentId: randomUUID() })),
    ];

    for (const refusal of refusals) {
      expect(refusal.error).toBeInstanceOf(NotFoundException);
      expectRefusal(refusal.response, 404);
      // Same body, same headers as every other refusal: a caller learns nothing
      // from the difference between one kind of failure and another -
      // not whether the link ever existed, nor whether the document does.
      expect(refusal.response.body).toEqual(refusals[0]?.response.body);
      expect(refusal.response.headers).toEqual(refusals[0]?.response.headers);
    }

    // Only the one served request ever reached the object store.
    expect(harness.storage.reads).toHaveLength(1);
  });

  it('answers a failed audit row with the generic 503 and no byte', async () => {
    const harness = await createHarness();
    const link = await harness.service.issueLink(owner(), { documentId: harness.document.id });

    harness.audit.failNext = true;

    const { response, error } = await view(harness, link.token);

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expectRefusal(response, 503);
    // Fail closed: the trail could not be written, so nothing was read.
    expect(harness.storage.reads).toHaveLength(0);
  });

  it('answers an unreadable blob with the generic 503, the view row already written', async () => {
    const harness = await createHarness();
    const link = await harness.service.issueLink(owner(), { documentId: harness.document.id });

    harness.storage.failNext = true;

    const { response, error } = await view(harness, link.token);

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expectRefusal(response, 503);
    expect(actionsOf(harness.audit)).toEqual([
      DOCUMENT_VIEW_ACTIONS.LINK_ISSUED,
      DOCUMENT_VIEW_ACTIONS.VIEWED,
    ]);
  });

  it.each([
    ['without a signing secret', { withoutSecret: true }],
    ['without a one-time store', { withoutStore: true }],
  ])('answers a deployment %s with the generic 503 and no byte', async (_label, options) => {
    const harness = await createHarness(options);
    const token = await sealedToken(harness);

    const { response, error } = await view(harness, token);

    expect(error).toBeInstanceOf(ServiceUnavailableException);
    expectRefusal(response, 503);
    expect(harness.storage.reads).toHaveLength(0);
  });

  it('keeps the token out of the log while still reporting the refusal', async () => {
    const harness = await createHarness();
    const token = await sealedToken(harness, {
      nowMs: Date.now() - (VIEW_LINK_TTL_SECONDS + 60) * 1000,
    });

    await view(harness, token);

    expect(harness.logger.warns).toHaveLength(1);
    expect(harness.logger.warns[0]?.[0]).toMatchObject({
      statusCode: 404,
      method: 'GET',
      path: VIEWED_FILE_ROUTE_PATTERN,
    });
    // The one-time link is the credential: the whole log stays free of it.
    expect(JSON.stringify(harness.logger.warns)).not.toContain(token);
  });
});
