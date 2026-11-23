import type { DocumentKind } from '@prisma/client';
import request from 'supertest';
import { Role } from '../src/auth/roles';
import type { DocumentStorage } from '../src/documents/document-storage';
import {
  DOCUMENT_AUDIT_ACTIONS,
  MAX_ACTIVE_DOCUMENTS,
} from '../src/documents/records/document-upload.service';
import type { IdentityDocumentRecord } from '../src/documents/records/identity-document.repository';
import { MAX_LISTED_DOCUMENTS } from '../src/documents/records/owner-documents.service';
import { InMemoryIdentityDocuments } from '../src/documents/records/testing/in-memory-identity-documents';
import type {
  ConsumeRateLimitInput,
  RateLimitDecision,
  RateLimitService,
} from '../src/rate-limit/rate-limit.service';
import { createAdminHarness, type AdminAccount, type AdminAuditRow } from './helpers/admin-harness';

/**
 * The owner's two routes over the real application:
 * `GET /athlete/documents` and `DELETE /athlete/documents/:documentId`.
 *
 * The guards, the global pipe, the audit chain and the limiter hook are the real
 * ones; only the table and the audit storage are in memory. What is proved here
 * is the contract: the list carries five fields and never the envelope, the
 * owner id or the quota; the delete answers 204 with no body and one identical
 * 404 for a missing, foreign or already deleted id; every refusal is either the
 * shared envelope or a generic one; and nothing a caller sends can name an owner.
 */

const UNAUTHORIZED = { statusCode: 401, message: 'Unauthorized' } as const;
const BAD_REQUEST = { statusCode: 400, message: 'Bad Request' } as const;
const NOT_FOUND = { statusCode: 404, message: 'Not Found' } as const;
const SERVICE_UNAVAILABLE = { statusCode: 503, message: 'Service Unavailable' } as const;

/** The five fields a list item may carry, and nothing else. */
const SUMMARY_FIELDS = ['contentType', 'createdAt', 'id', 'kind', 'sizeBytes'];

/** A valid id that belongs to nobody, for the 404 cases. */
const MISSING_ID = '99999999-9999-4999-8999-999999999999';

interface OwnerHarnessOptions {
  readonly documents?: InMemoryIdentityDocuments;
  readonly rateLimit?: RateLimitService;
  /** A client that fails on purpose, e.g. to make the audit append fail. */
  readonly prisma?: object;
  /** A store that records deletes, so "the blob is left alone" is provable. */
  readonly storage?: RecordingStorage;
}

/** A store that only remembers what was deleted, so a delete of a blob would show. */
class RecordingStorage implements DocumentStorage {
  private readonly objects = new Map<string, Buffer>();
  readonly deletes: string[] = [];

  async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.objects.set(objectKey, bytes);
  }

  async get(objectKey: string): Promise<Buffer> {
    const found = this.objects.get(objectKey);

    if (found === undefined) throw new Error('no such object');

    return found;
  }

  async delete(objectKey: string): Promise<void> {
    this.deletes.push(objectKey);
    this.objects.delete(objectKey);
  }

  async exists(objectKey: string): Promise<boolean> {
    return this.objects.has(objectKey);
  }
}

/** The real application over in-memory documents and an in-memory audit table. */
async function createOwnerHarness(prefix: string, options: OwnerHarnessOptions = {}) {
  const documents = options.documents ?? new InMemoryIdentityDocuments();
  const storage = options.storage ?? new RecordingStorage();

  const harness = await createAdminHarness(prefix, {
    identityDocumentRepository: documents,
    documentStorage: storage,
    ...(options.rateLimit === undefined ? {} : { rateLimit: options.rateLimit }),
    ...(options.prisma === undefined ? {} : { prisma: options.prisma }),
  });

  return { ...harness, documents, storage };
}

type OwnerHarness = Awaited<ReturnType<typeof createOwnerHarness>>;

/** Admits every other scope, refuses one, and keeps every input it saw. */
class RefusingOwnerLimit {
  readonly consumed: ConsumeRateLimitInput[] = [];

  constructor(
    private readonly refused: string,
    private readonly retryAfterSeconds = 120,
  ) {}

  async consume(input: ConsumeRateLimitInput): Promise<RateLimitDecision> {
    this.consumed.push(input);

    return input.scope === this.refused
      ? { allowed: false, remaining: 0, retryAfterSeconds: this.retryAfterSeconds }
      : { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  /** The read-only variant: reports the same budget without billing a hit. */
  async peek(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
}

/** A table that cannot list, for the read-side fail-closed answer. */
class UnlistableDocuments extends InMemoryIdentityDocuments {
  override async listActiveByOwner(): Promise<IdentityDocumentRecord[]> {
    throw new Error('database is unavailable');
  }
}

/**
 * A client whose delete entry cannot be appended, while every other entry (the
 * registration of the fixture, say) still is. Its transaction restores the table
 * when the callback throws - the rollback the real database performs.
 */
function createFailingDeleteAuditPrisma(documents: InMemoryIdentityDocuments): {
  prisma: object;
  rows: AdminAuditRow[];
} {
  const rows: AdminAuditRow[] = [];

  const tx = {
    $executeRaw: (): Promise<number> => Promise.resolve(1),
    auditLog: {
      findFirst: (): Promise<{ hash: string; createdAt: Date } | null> => {
        const last = rows[rows.length - 1];

        return Promise.resolve(
          last === undefined ? null : { hash: last.hash, createdAt: last.createdAt },
        );
      },
      create: ({ data }: { data: AdminAuditRow }): Promise<AdminAuditRow> => {
        // Only the delete entry is refused, so the fixture can still sign up.
        if (data.action === DOCUMENT_AUDIT_ACTIONS.DELETED) {
          return Promise.reject(new Error('the audit chain is unavailable'));
        }

        rows.push(data);

        return Promise.resolve(data);
      },
    },
  };

  const prisma = {
    $connect: (): Promise<void> => Promise.resolve(),
    $disconnect: (): Promise<void> => Promise.resolve(),
    // No profile is under review here, so the delete lock never applies.
    athleteProfile: { findUnique: (): Promise<null> => Promise.resolve(null) },
    $transaction: async (run: (client: typeof tx) => Promise<unknown>): Promise<unknown> => {
      const before = documents.snapshot();

      try {
        return await run(tx);
      } catch (error) {
        documents.restore(before);

        throw error;
      }
    },
  };

  return { prisma, rows };
}

describe('GET /athlete/documents (e2e)', () => {
  const documents = new InMemoryIdentityDocuments();
  let harness: OwnerHarness;

  const newAthlete = (): Promise<AdminAccount> => harness.signUp(Role.ATHLETE);
  const listOf = async (token: string) => harness.get('/athlete/documents', token);

  beforeAll(async () => {
    harness = await createOwnerHarness('owner_list', { documents });
  });

  afterAll(async () => {
    await harness.close();
  });

  it('refuses the list without a token and reads nothing', async () => {
    const response = await request(harness.app.getHttpServer()).get('/athlete/documents');

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    expect(documents.lists).toEqual([]);
  });

  it('answers an empty list for an account with no documents, uncacheable', async () => {
    const account = await newAthlete();
    const response = await listOf(account.token);

    expect(response.status).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toEqual({ documents: [] });
    expect(documents.lists[documents.lists.length - 1]).toEqual({
      ownerUserId: account.userId,
      limit: MAX_LISTED_DOCUMENTS,
    });
  });

  it('lists the owner ACTIVE documents newest first, with five fields only', async () => {
    const account = await newAthlete();
    const stranger = await newAthlete();

    const oldest = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));
    const newest = documents.seed(
      account.userId,
      new Date('2026-03-01T00:00:00.000Z'),
      'MEDAL' as DocumentKind,
    );
    const middle = documents.seed(account.userId, new Date('2026-02-01T00:00:00.000Z'));
    const gone = documents.seed(account.userId, new Date('2026-04-01T00:00:00.000Z'));
    const foreign = documents.seed(stranger.userId, new Date('2026-05-01T00:00:00.000Z'));

    documents.softDelete(gone.id);

    const response = await listOf(account.token);
    const listed = (response.body as { documents: Record<string, unknown>[] }).documents;

    expect(response.status).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(listed.map((item) => item.id)).toEqual([newest.id, middle.id, oldest.id]);
    expect(listed.map((item) => item.id)).not.toContain(gone.id);
    expect(listed.map((item) => item.id)).not.toContain(foreign.id);

    for (const item of listed) {
      expect(Object.keys(item).sort()).toEqual(SUMMARY_FIELDS);
    }

    // Nothing that would locate, fingerprint, decrypt or own the object.
    const body = JSON.stringify(response.body);

    expect(body).not.toContain(oldest.objectKey);
    expect(body).not.toContain(oldest.sha256);
    expect(body).not.toContain(oldest.keyId);
    expect(body).not.toContain(account.userId);
    expect(response.body).not.toHaveProperty('quota');
    expect(response.body).not.toHaveProperty('limit');
  });

  it("answers any signed-in role with its own documents and nobody else's", async () => {
    const user = await harness.signUp(Role.USER);
    const athlete = await newAthlete();
    const own = documents.seed(user.userId, new Date('2026-01-01T00:00:00.000Z'));
    const other = documents.seed(athlete.userId, new Date('2026-02-01T00:00:00.000Z'));

    const response = await listOf(user.token);
    const ids = (response.body as { documents: { id: string }[] }).documents.map((item) => item.id);

    expect(response.status).toBe(200);
    expect(ids).toEqual([own.id]);
    expect(ids).not.toContain(other.id);
  });

  it('refuses an unknown query key with 400 and never reads the table', async () => {
    const account = await newAthlete();
    const reads = documents.lists.length;

    const response = await request(harness.app.getHttpServer())
      .get(`/athlete/documents?ownerUserId=${account.userId}`)
      .set('Authorization', `Bearer ${account.token}`);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(documents.lists).toHaveLength(reads);
  });

  it('refuses a body on the list with 400, so no owner can be named', async () => {
    const account = await newAthlete();
    const reads = documents.lists.length;

    const response = await request(harness.app.getHttpServer())
      .get('/athlete/documents')
      .set('Authorization', `Bearer ${account.token}`)
      .send({ ownerUserId: account.userId });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(documents.lists).toHaveLength(reads);
  });
});

describe('DELETE /athlete/documents/:documentId (e2e)', () => {
  const documents = new InMemoryIdentityDocuments();
  let harness: OwnerHarness;

  const newAthlete = (): Promise<AdminAccount> => harness.signUp(Role.ATHLETE);
  const deleteOf = (token: string, documentId: string) =>
    harness.del(`/athlete/documents/${documentId}`, token);
  const stored = (documentId: string) => documents.rows.find((row) => row.id === documentId);

  beforeAll(async () => {
    harness = await createOwnerHarness('owner_delete', { documents });
  });

  afterAll(async () => {
    await harness.close();
  });

  it('refuses the delete without a token and leaves the row ACTIVE', async () => {
    const row = documents.seed(
      '77777777-7777-4777-8777-777777777777',
      new Date('2026-01-01T00:00:00.000Z'),
    );
    const response = await request(harness.app.getHttpServer()).delete(
      `/athlete/documents/${row.id}`,
    );

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ ...UNAUTHORIZED, requestId: expect.any(String) });
    expect(stored(row.id)?.status).toBe('ACTIVE');
    expect(documents.deletions).toEqual([]);
  });

  it('soft-deletes the owner document, answers 204, and records one entry', async () => {
    const account = await newAthlete();
    const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'), 'MEDAL');

    const response = await deleteOf(account.token, row.id);

    expect(response.status).toBe(204);
    expect(response.body).toEqual({});
    expect(response.text).toBe('');
    expect(response.headers['cache-control']).toBe('no-store');

    const after = stored(row.id);

    expect(after?.status).toBe('DELETED');
    expect(after?.deletedAt).toBeInstanceOf(Date);
    // The row is otherwise untouched, and the blob is left for the retention job.
    expect(after?.objectKey).toBe(row.objectKey);
    expect(after?.sha256).toBe(row.sha256);
    expect(after?.sizeBytes).toBe(row.sizeBytes);
    expect(harness.storage.deletes).toEqual([]);

    const entries = harness.rows(DOCUMENT_AUDIT_ACTIONS.DELETED, row.id);

    expect(entries).toHaveLength(1);
    expect(entries[0]?.actorId).toBe(account.userId);
    expect(Object.keys(entries[0]?.metadata ?? {}).sort()).toEqual(['documentId', 'kind']);
    expect(entries[0]?.metadata).toMatchObject({ documentId: row.id, kind: 'MEDAL' });
  });

  it('answers the same 404 for an id that belongs to nobody', async () => {
    const account = await newAthlete();
    const response = await deleteOf(account.token, MISSING_ID);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    expect(harness.rows(DOCUMENT_AUDIT_ACTIONS.DELETED, MISSING_ID)).toEqual([]);
  });

  it('answers the same 404 for a document of another account, and leaves it ACTIVE', async () => {
    const owner = await newAthlete();
    const stranger = await newAthlete();
    const row = documents.seed(owner.userId, new Date('2026-01-01T00:00:00.000Z'));

    const response = await deleteOf(stranger.token, row.id);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    expect(stored(row.id)?.status).toBe('ACTIVE');
    expect(harness.rows(DOCUMENT_AUDIT_ACTIONS.DELETED, row.id)).toEqual([]);
  });

  it('answers the same 404 on a second delete, and records nothing more', async () => {
    const account = await newAthlete();
    const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));

    expect((await deleteOf(account.token, row.id)).status).toBe(204);

    const deletedAt = stored(row.id)?.deletedAt;
    const again = await deleteOf(account.token, row.id);

    expect(again.status).toBe(404);
    expect(again.body).toEqual({ ...NOT_FOUND, requestId: expect.any(String) });
    expect(stored(row.id)?.deletedAt).toBe(deletedAt);
    expect(harness.rows(DOCUMENT_AUDIT_ACTIONS.DELETED, row.id)).toHaveLength(1);
  });

  it('drops the document from the list and frees its quota slot', async () => {
    const account = await newAthlete();

    documents.seedActive(account.userId, MAX_ACTIVE_DOCUMENTS);

    const row = documents.rows.find((candidate) => candidate.ownerUserId === account.userId);

    expect(await documents.countActiveByOwner(account.userId)).toBe(MAX_ACTIVE_DOCUMENTS);
    expect((await deleteOf(account.token, row!.id)).status).toBe(204);
    expect(await documents.countActiveByOwner(account.userId)).toBe(MAX_ACTIVE_DOCUMENTS - 1);

    const listed = (await harness.get('/athlete/documents', account.token)).body as {
      documents: { id: string }[];
    };

    expect(listed.documents.map((item) => item.id)).not.toContain(row?.id);
    expect(listed.documents).toHaveLength(MAX_ACTIVE_DOCUMENTS - 1);
  });

  it('refuses a malformed id with 400, before the table is touched', async () => {
    const account = await newAthlete();
    const attempts = documents.deletions.length;
    const response = await deleteOf(account.token, 'not-a-uuid');

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(documents.deletions).toHaveLength(attempts);
  });

  it('refuses an unknown query key with 400, so no owner can be named', async () => {
    const account = await newAthlete();
    const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));
    const response = await harness.del(
      `/athlete/documents/${row.id}?ownerUserId=${account.userId}`,
      account.token,
    );

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(stored(row.id)?.status).toBe('ACTIVE');
  });

  it('refuses a body with 400, so no owner or status can be named', async () => {
    const account = await newAthlete();
    const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));

    const response = await request(harness.app.getHttpServer())
      .delete(`/athlete/documents/${row.id}`)
      .set('Authorization', `Bearer ${account.token}`)
      .send({ status: 'ACTIVE', ownerUserId: account.userId });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ ...BAD_REQUEST, requestId: expect.any(String) });
    expect(stored(row.id)?.status).toBe('ACTIVE');
  });
});

/**
 * The two counters, over the real routes: the limiter refuses one scope, and the
 * answer is the shared 429 envelope with the same `Retry-After` every other
 * limited route sends.
 */
describe('Owner document limits (e2e)', () => {
  it('answers 429 for the delete scope and leaves the document ACTIVE', async () => {
    const limiter = new RefusingOwnerLimit('document-delete');
    const documents = new InMemoryIdentityDocuments();
    const harness = await createOwnerHarness('owner_limited_delete', {
      documents,
      rateLimit: limiter as unknown as RateLimitService,
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));

      const response = await harness.del(`/athlete/documents/${row.id}`, account.token);

      expect(response.status).toBe(429);
      expect(response.body).toEqual({
        statusCode: 429,
        message: 'Too Many Requests',
        requestId: expect.any(String),
      });
      expect(response.headers['retry-after']).toBe('120');

      // Per user, in the delete scope, one window an hour.
      const charged = limiter.consumed.filter((input) => input.scope === 'document-delete');

      expect(charged).toEqual([
        {
          scope: 'document-delete',
          identifier: account.userId,
          limit: 20,
          windowSeconds: 3_600,
        },
      ]);
      expect(documents.rows.find((candidate) => candidate.id === row.id)?.status).toBe('ACTIVE');
      expect(harness.rows(DOCUMENT_AUDIT_ACTIONS.DELETED)).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  it('answers 429 for the list scope, and a spent list budget leaves the delete open', async () => {
    const limiter = new RefusingOwnerLimit('document-list', 30);
    const documents = new InMemoryIdentityDocuments();
    const harness = await createOwnerHarness('owner_limited_list', {
      documents,
      rateLimit: limiter as unknown as RateLimitService,
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'));

      const refused = await harness.get('/athlete/documents', account.token);

      expect(refused.status).toBe(429);
      expect(refused.headers['retry-after']).toBe('30');

      const charged = limiter.consumed.filter((input) => input.scope === 'document-list');

      expect(charged).toEqual([
        {
          scope: 'document-list',
          identifier: account.userId,
          limit: 60,
          windowSeconds: 60,
        },
      ]);

      // The other scope is untouched: a spent list budget never closes the delete.
      expect((await harness.del(`/athlete/documents/${row.id}`, account.token)).status).toBe(204);
    } finally {
      await harness.close();
    }
  });
});

/**
 * The read and the delete when a dependency fails: one generic 503 each, the
 * document left exactly as it was, and no trail entry for a delete that did not
 * happen.
 */
describe('Owner documents with a failing dependency (e2e)', () => {
  it('answers 503 and keeps the document ACTIVE when its entry cannot be written', async () => {
    const documents = new InMemoryIdentityDocuments();
    const failing = createFailingDeleteAuditPrisma(documents);
    const harness = await createOwnerHarness('owner_audit_down', {
      documents,
      prisma: failing.prisma,
    });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const row = documents.seed(account.userId, new Date('2026-01-01T00:00:00.000Z'), 'MEDAL');
      const response = await harness.del(`/athlete/documents/${row.id}`, account.token);

      expect(response.status).toBe(503);
      expect(response.body).toEqual({ ...SERVICE_UNAVAILABLE, requestId: expect.any(String) });
      expect(response.headers['cache-control']).toBe('no-store');

      // The transaction rolled back, and nothing claims the document was deleted.
      const after = documents.rows.find((candidate) => candidate.id === row.id);

      expect(after?.status).toBe('ACTIVE');
      expect(after?.deletedAt).toBeNull();

      const trail = failing.rows.filter((entry) => entry.action === DOCUMENT_AUDIT_ACTIONS.DELETED);

      expect(trail).toEqual([]);
    } finally {
      await harness.close();
    }
  });

  it('answers 503, uncacheable, when the table cannot be read', async () => {
    const documents = new UnlistableDocuments();
    const harness = await createOwnerHarness('owner_read_down', { documents });

    try {
      const account = await harness.signUp(Role.ATHLETE);
      const response = await harness.get('/athlete/documents', account.token);

      expect(response.status).toBe(503);
      expect(response.body).toEqual({ ...SERVICE_UNAVAILABLE, requestId: expect.any(String) });
      expect(response.headers['cache-control']).toBe('no-store');
    } finally {
      await harness.close();
    }
  });
});
