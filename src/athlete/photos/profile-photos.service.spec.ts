import {
  BadRequestException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { createHash, randomUUID } from 'node:crypto';
import type { PinoLogger } from 'nestjs-pino';
import { FakeAudit, type AuditRecord } from '../../../test/helpers/auth-service-harness';
import type { AuditService } from '../../audit/audit.service';
import type { PolicySubject } from '../../auth/policy/access-policy';
import type { AccessPolicyContext } from '../../auth/policy/access-policy.service';
import { Role } from '../../auth/roles';
import type { PrismaService } from '../../database/prisma.service';
import {
  DocumentCryptoService,
  type EncryptedDocument,
} from '../../documents/document-crypto.service';
import { EnvKeyWrapper } from '../../documents/env-key-wrapper';
import { InMemoryDocumentStorage } from '../../documents/in-memory-document-storage';
import { DocumentIngestService } from '../../documents/ingest/document-ingest.service';
import { DocumentIngestError } from '../../documents/ingest/ingest.errors';
import { buildPng, TEXT_CHUNK } from '../../documents/ingest/testing/image-fixtures';
import { FakeVirusScanner } from '../../documents/ingest/testing/fake-virus-scanner';
import { MAX_PHOTO_CAPTION_LENGTH, parsePhotoId, parsePhotoUploadQuery } from './profile-photo.dto';
import type { ProfilePhotoInsert, ProfilePhotoRecord } from './profile-photo.repository';
import {
  MAX_PROFILE_PHOTOS,
  MAX_PROFILE_PHOTO_LIST,
  PROFILE_PHOTO_AUDIT_ACTIONS,
  ProfilePhotosService,
  type ProfilePhotoUploadRequest,
} from './profile-photos.service';
import { InMemoryProfilePhotos } from './testing/in-memory-profile-photos';

/** Fixed, fake master key: base64 of exactly 32 bytes. */
const MASTER_KEY = 'a2ZhLXRlc3Qtb25seS1kb2N1bWVudC1tYXN0ZXIta2U=';
const USER_ID = '33333333-3333-4333-8333-333333333333';
const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_PROFILE_ID = '22222222-2222-4222-8222-222222222222';
/** A comment chunk, so the sanitizer has something to strip and something to prove. */
const COMMENT = Buffer.from('test-only photo', 'latin1');

const PNG = buildPng({ chunks: [TEXT_CHUNK] });

const actor: PolicySubject = { id: USER_ID, role: Role.ATHLETE };
const CONTEXT: AccessPolicyContext = { requestId: 'req-1', ip: '203.0.113.7' };

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class RecordingPhotos extends InMemoryProfilePhotos {
  failInsert = false;

  override async insert(
    record: ProfilePhotoInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<ProfilePhotoRecord> {
    if (this.failInsert) {
      this.failInsert = false;

      throw new Error('database is unavailable');
    }

    return super.insert(record, tx);
  }
}

class RecordingStorage extends InMemoryDocumentStorage {
  readonly puts: string[] = [];
  readonly deletes: string[] = [];
  failPut = false;

  override async put(objectKey: string, bytes: Buffer): Promise<void> {
    this.puts.push(objectKey);

    if (this.failPut) throw new Error('storage is unavailable');

    await super.put(objectKey, bytes);
  }

  override async delete(objectKey: string): Promise<void> {
    this.deletes.push(objectKey);

    await super.delete(objectKey);
  }
}

class RecordingAudit extends FakeAudit {
  fail = false;

  override async record(entry: AuditRecord, tx?: unknown): Promise<void> {
    if (this.fail) throw new Error('audit chain is unavailable');

    await super.record(entry, tx);
  }
}

class RecordingCrypto extends DocumentCryptoService {
  fail = false;

  constructor() {
    super(new EnvKeyWrapper({ masterKey: MASTER_KEY }));
  }

  override async encrypt(plaintext: Buffer, aad: string): Promise<EncryptedDocument> {
    if (this.fail) throw new Error('key service is unavailable');

    return super.encrypt(plaintext, aad);
  }
}

class QuietLogger {
  readonly warns: unknown[] = [];

  warn(payload: unknown): void {
    this.warns.push(payload);
  }
}

/**
 * The one thing the service needs from Prisma: the caller's profile row and an
 * interactive transaction. A throw from the callback discards what the callback
 * wrote, the way the real client does.
 */
class FakePrisma {
  profileId: string | null = PROFILE_ID;
  readonly transactions: Prisma.TransactionClient[] = [];
  readonly options: unknown[] = [];

  readonly athleteProfile = {
    findUnique: (): Promise<{ id: string } | null> =>
      Promise.resolve(this.profileId === null ? null : { id: this.profileId }),
  };

  constructor(private readonly photos: RecordingPhotos) {}

  async $transaction<T>(
    run: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: unknown,
  ): Promise<T> {
    const tx = { isTransaction: true } as unknown as Prisma.TransactionClient;

    this.transactions.push(tx);
    this.options.push(options);

    const before = this.photos.snapshot();

    try {
      return await run(tx);
    } catch (error) {
      this.photos.restore(before);

      throw error;
    }
  }
}

function createService() {
  const photos = new RecordingPhotos();
  const storage = new RecordingStorage();
  const scanner = new FakeVirusScanner();
  const audit = new RecordingAudit();
  const crypto = new RecordingCrypto();
  const logger = new QuietLogger();
  const prisma = new FakePrisma(photos);
  const service = new ProfilePhotosService(
    prisma as unknown as PrismaService,
    photos,
    new DocumentIngestService(scanner),
    crypto,
    storage,
    audit as unknown as AuditService,
    logger as unknown as PinoLogger,
  );

  return { service, photos, storage, scanner, audit, crypto, logger, prisma };
}

function upload(
  service: ProfilePhotosService,
  overrides: Partial<ProfilePhotoUploadRequest> = {},
): ReturnType<ProfilePhotosService['upload']> {
  return service.upload(
    actor,
    { bytes: PNG, claimedMime: 'image/png', caption: null, ...overrides },
    CONTEXT,
  );
}

describe('ProfilePhotosService upload', () => {
  it('stores ciphertext under a random key and answers the owner fields only', async () => {
    const { service, photos, storage, scanner, crypto, audit, prisma } = createService();

    const view = await upload(service, { caption: 'On the podium' });
    const row = photos.rows[0] as ProfilePhotoRecord;
    const sanitized = scanner.received[0] as Buffer;

    // What the caller gets, and nothing else.
    expect(Object.keys(view).sort()).toEqual([
      'caption',
      'contentType',
      'createdAt',
      'id',
      'reviewedAt',
      'sizeBytes',
      'status',
    ]);
    expect(view).toMatchObject({
      id: row.id,
      caption: 'On the podium',
      status: 'PENDING',
      contentType: 'image/png',
      sizeBytes: sanitized.length,
      reviewedAt: null,
    });
    expect(JSON.stringify(view)).not.toContain(row.objectKey);
    expect(JSON.stringify(view)).not.toContain(row.sha256);
    expect(JSON.stringify(view)).not.toContain(PROFILE_ID);

    // A new photo is always PENDING: no request value reached the status column.
    expect(row).toMatchObject({
      athleteProfileId: PROFILE_ID,
      status: 'PENDING',
      reviewedAt: null,
      reviewedById: null,
      keyId: 'v1',
    });
    expect(row.sizeBytes).toBe(sanitized.length);
    expect(row.sha256).toBe(sha256(sanitized));
    expect(row.objectKey).not.toContain(USER_ID);
    expect(row.objectKey).not.toContain(PROFILE_ID);
    expect(row.iv).toHaveLength(12);
    expect(row.authTag).toHaveLength(16);

    // Only ciphertext is stored, and it reads back only under its own key.
    const stored = await storage.get(row.objectKey);

    expect(stored.equals(sanitized)).toBe(false);
    expect(stored.includes(COMMENT)).toBe(false);
    expect(storage.puts).toEqual([row.objectKey]);
    expect(
      (
        await crypto.decrypt(
          {
            ciphertext: stored,
            iv: row.iv,
            authTag: row.authTag,
            wrappedDek: row.wrappedDek,
            keyId: row.keyId,
          },
          row.objectKey,
        )
      ).equals(sanitized),
    ).toBe(true);

    // The row and its trail joined one transaction.
    expect(photos.transactions).toEqual([prisma.transactions[0]]);
    expect(audit.transactions).toEqual([prisma.transactions[0]]);
  });

  it('writes one audit entry per upload, without the caption text or the key', async () => {
    const { service, photos, audit } = createService();

    await upload(service, { caption: 'On the podium' });

    const row = photos.rows[0] as ProfilePhotoRecord;

    expect(audit.records).toHaveLength(1);
    expect(audit.records[0]).toMatchObject({
      action: PROFILE_PHOTO_AUDIT_ACTIONS.UPLOADED,
      actorId: USER_ID,
      actorRole: 'ATHLETE',
      targetType: 'profile_photo',
      targetId: row.id,
      requestId: 'req-1',
      ip: '203.0.113.7',
    });
    expect(audit.records[0]?.metadata).toEqual({
      photoId: row.id,
      status: 'PENDING',
      contentType: 'image/png',
      sizeBytes: row.sizeBytes,
      hasCaption: true,
    });

    const trail = JSON.stringify(audit.records);

    expect(trail).not.toContain('On the podium');
    expect(trail).not.toContain(row.objectKey);
    expect(trail).not.toContain(row.sha256);
  });

  it('refuses an over-quota upload before scanning, encrypting or storing', async () => {
    const { service, photos, storage, scanner, audit, prisma } = createService();

    for (let index = 0; index < MAX_PROFILE_PHOTOS - 1; index += 1) {
      photos.seed(PROFILE_ID, 'APPROVED');
    }

    photos.seed(PROFILE_ID, 'PENDING');

    await expect(upload(service)).rejects.toBeInstanceOf(DocumentIngestError);

    expect(photos.counts).toEqual([PROFILE_ID]);
    expect(scanner.received).toHaveLength(0);
    expect(storage.puts).toHaveLength(0);
    expect(photos.inserts).toHaveLength(0);
    expect(prisma.transactions).toHaveLength(0);
    expect(audit.records).toHaveLength(0);
  });

  it('does not charge rejected photos against the quota', async () => {
    const { service, photos } = createService();

    for (let index = 0; index < MAX_PROFILE_PHOTOS; index += 1) {
      photos.seed(PROFILE_ID, 'REJECTED');
    }

    for (let index = 0; index < MAX_PROFILE_PHOTOS - 1; index += 1) {
      photos.seed(PROFILE_ID, 'APPROVED');
    }

    const view = await upload(service);

    expect(view.status).toBe('PENDING');
    expect(photos.inserts).toHaveLength(1);
  });

  it('answers a generic 404 when the account has no profile yet', async () => {
    const { service, photos, storage, scanner, prisma } = createService();

    prisma.profileId = null;

    await expect(upload(service)).rejects.toBeInstanceOf(NotFoundException);

    expect(photos.counts).toHaveLength(0);
    expect(scanner.received).toHaveLength(0);
    expect(storage.puts).toHaveLength(0);
    expect(photos.inserts).toHaveLength(0);
  });

  it('rolls the row back and removes the blob when the trail cannot be written', async () => {
    const { service, photos, storage, audit, logger } = createService();

    audit.fail = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(photos.rows).toHaveLength(0);
    expect(audit.records).toHaveLength(0);
    expect(storage.deletes).toEqual(storage.puts);
    expect(storage.deletes).toHaveLength(1);
    expect(logger.warns[0]).toMatchObject({ stage: 'persist' });
  });

  it('writes nothing when the object store refuses the ciphertext', async () => {
    const { service, photos, storage, audit } = createService();

    storage.failPut = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(photos.inserts).toHaveLength(0);
    expect(audit.records).toHaveLength(0);
    expect(storage.deletes).toHaveLength(0);
  });

  it('removes the blob when the row cannot be inserted', async () => {
    const { service, photos, storage } = createService();

    photos.failInsert = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(photos.rows).toHaveLength(0);
    expect(storage.deletes).toEqual(storage.puts);
  });

  it('answers a generic 503 when encryption is unavailable', async () => {
    const { service, photos, storage, crypto, logger } = createService();

    crypto.fail = true;

    await expect(upload(service)).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(storage.puts).toHaveLength(0);
    expect(photos.inserts).toHaveLength(0);
    expect(logger.warns[0]).toMatchObject({ stage: 'encrypt' });
  });
});

describe('ProfilePhotosService read paths', () => {
  it('lists only the caller’s photos, newest first and capped', async () => {
    const { service, photos } = createService();
    const older = photos.seed(PROFILE_ID, 'APPROVED', new Date('2026-01-01T00:00:00.000Z'));
    const newer = photos.seed(PROFILE_ID, 'PENDING', new Date('2026-02-01T00:00:00.000Z'));

    photos.seed(OTHER_PROFILE_ID, 'APPROVED', new Date('2026-03-01T00:00:00.000Z'));

    const list = await service.list(actor);

    expect(list.photos.map((photo) => photo.id)).toEqual([newer.id, older.id]);
    expect(photos.lists).toEqual([{ athleteProfileId: PROFILE_ID, limit: MAX_PROFILE_PHOTO_LIST }]);
    expect(list.photos[0]).not.toHaveProperty('objectKey');
    expect(list.photos[0]).not.toHaveProperty('sha256');
    expect(JSON.stringify(list)).not.toContain(OTHER_PROFILE_ID);
  });

  it('answers an empty list when the account has no profile yet', async () => {
    const { service, photos, prisma } = createService();

    prisma.profileId = null;

    await expect(service.list(actor)).resolves.toEqual({ photos: [] });
    expect(photos.lists).toHaveLength(0);
  });

  it('reads an own photo and refuses a foreign one exactly like a missing one', async () => {
    const { service, photos } = createService();
    const mine = photos.seed(PROFILE_ID, 'APPROVED');
    const foreign = photos.seed(OTHER_PROFILE_ID, 'APPROVED');

    const missing = randomUUID();

    await expect(service.read(actor, mine.id)).resolves.toMatchObject({
      id: mine.id,
      status: 'APPROVED',
    });
    await expect(service.read(actor, foreign.id)).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.read(actor, missing)).rejects.toBeInstanceOf(NotFoundException);

    // Every read was scoped to the caller's own profile, never to the id alone.
    expect(photos.reads).toEqual([
      { photoId: mine.id, athleteProfileId: PROFILE_ID },
      { photoId: foreign.id, athleteProfileId: PROFILE_ID },
      { photoId: missing, athleteProfileId: PROFILE_ID },
    ]);
  });

  it('answers a generic 404 when a profile-less account reads a photo', async () => {
    const { service, photos, prisma } = createService();

    prisma.profileId = null;

    await expect(service.read(actor, randomUUID())).rejects.toBeInstanceOf(NotFoundException);
    expect(photos.reads).toHaveLength(0);
  });
});

describe('photo caption', () => {
  it('is optional, and a blank one is stored as no caption', () => {
    expect(parsePhotoUploadQuery({})).toEqual({ caption: null });
    expect(parsePhotoUploadQuery({ caption: '   ' })).toEqual({ caption: null });
  });

  it('trims, collapses whitespace and escapes markup', () => {
    expect(parsePhotoUploadQuery({ caption: '  First   race  ' }).caption).toBe('First race');
    expect(parsePhotoUploadQuery({ caption: '<b>&"\'</b>' }).caption).toBe(
      '&lt;b&gt;&amp;&#34;&#39;&lt;/b&gt;',
    );
  });

  it('removes control characters instead of storing them', () => {
    expect(parsePhotoUploadQuery({ caption: 'line\u0000one\nline\ttwo' }).caption).toBe(
      'line one line two',
    );
  });

  it('refuses a caption over the cap, a non-string, or an unknown key', () => {
    const tooLong = 'a'.repeat(MAX_PHOTO_CAPTION_LENGTH + 1);

    expect(() => parsePhotoUploadQuery({ caption: tooLong })).toThrow(BadRequestException);
    expect(() => parsePhotoUploadQuery({ caption: ['one', 'two'] })).toThrow(BadRequestException);
    expect(() => parsePhotoUploadQuery({ caption: 'ok', status: 'APPROVED' })).toThrow(
      BadRequestException,
    );
  });

  it('keeps the escaped form inside the column for a worst-case caption', () => {
    // Every character becomes the longest entity, so this is the column's worst case.
    const escaped = parsePhotoUploadQuery({
      caption: '&'.repeat(MAX_PHOTO_CAPTION_LENGTH),
    }).caption;

    expect(escaped).not.toBeNull();
    expect(escaped?.length).toBeLessThanOrEqual(1_000);
  });

  it('checks the photo id before it reaches the service', () => {
    const id = randomUUID();

    expect(parsePhotoId(id)).toBe(id);
    expect(() => parsePhotoId('../../etc/passwd')).toThrow(BadRequestException);
    expect(() => parsePhotoId(undefined)).toThrow(BadRequestException);
  });
});
