import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { PrismaService } from '../../src/database/prisma.service';
import type { IdentityDocumentInsert } from '../../src/documents/records/identity-document.repository';
import { PrismaIdentityDocumentRepository } from '../../src/documents/records/prisma-identity-document.repository';
import {
  TEST_BREAK_GLASS_URL,
  createBreakGlassPrisma,
  createTestPrisma,
  describeWithDatabase,
} from './helpers/database';

/**
 * Stage 4.3b: the identity-document table against a real PostgreSQL, as `kfa_app`.
 *
 * The upload service is covered by unit specs; what only the database can prove
 * is here - the format CHECKs, the unique object key, the RESTRICT foreign key
 * and the withheld DELETE privilege.
 *
 * `kfa_app` may not delete a document, so the rows this suite writes are removed
 * by the break-glass client when one is configured (DATABASE_URL_TEST_BREAK_GLASS
 * pointing at `kfa_migrator`); without it they stay in the throwaway test
 * database, which is what the other database suites do as well.
 */

const unique = (prefix: string) => `${prefix}_${randomUUID().replaceAll('-', '')}`.slice(0, 30);

function phone(): string {
  return `+1415${randomUUID()
    .replace(/[^0-9]/g, '4')
    .slice(0, 7)}`;
}

function document(
  ownerUserId: string,
  overrides: Partial<IdentityDocumentInsert> = {},
): IdentityDocumentInsert {
  return {
    ownerUserId,
    kind: 'NATIONAL_ID',
    objectKey: randomUUID(),
    contentType: 'image/jpeg',
    sizeBytes: 2_048,
    sha256: 'a1'.repeat(32),
    keyId: 'v1',
    wrappedDek: Buffer.alloc(61, 7),
    iv: Buffer.alloc(12, 8),
    authTag: Buffer.alloc(16, 9),
    ...overrides,
  };
}

/**
 * `Buffer` is a `Uint8Array`, but Prisma types the `Bytes` columns as
 * `Uint8Array<ArrayBuffer>`, so the raw writes below go through plain views.
 */
function columns(input: IdentityDocumentInsert) {
  return {
    ...input,
    wrappedDek: new Uint8Array(input.wrappedDek),
    iv: new Uint8Array(input.iv),
    authTag: new Uint8Array(input.authTag),
  };
}

describeWithDatabase('identity document persistence (PostgreSQL)', () => {
  let prisma: PrismaClient;
  let repository: PrismaIdentityDocumentRepository;
  const userIds: string[] = [];

  /** ADMIN, not OWNER: the row trigger only fences the single owner account. */
  const newUser = async (): Promise<string> => {
    const user = await prisma.user.create({
      data: { phone: phone(), username: unique('document'), role: 'ADMIN' },
    });

    userIds.push(user.id);

    return user.id;
  };

  beforeAll(async () => {
    prisma = createTestPrisma();
    await prisma.$connect();
    repository = new PrismaIdentityDocumentRepository(prisma as unknown as PrismaService);
  });

  afterAll(async () => {
    if (!prisma) return;

    if (TEST_BREAK_GLASS_URL) {
      const root = createBreakGlassPrisma();

      await root.identityDocument.deleteMany({ where: { ownerUserId: { in: userIds } } });
      await root.user.deleteMany({ where: { id: { in: userIds } } });
      await root.$disconnect();
    }

    await prisma.$disconnect();
  });

  it('stores one row and reads it back with the envelope intact', async () => {
    const userId = await newUser();
    const input = document(userId);

    const saved = await repository.insert(input);

    expect(saved).toMatchObject({
      ownerUserId: userId,
      kind: 'NATIONAL_ID',
      objectKey: input.objectKey,
      contentType: 'image/jpeg',
      sizeBytes: 2_048,
      sha256: input.sha256,
      keyId: 'v1',
      status: 'ACTIVE',
      deletedAt: null,
    });
    expect(saved.wrappedDek).toEqual(input.wrappedDek);
    expect(saved.iv).toEqual(input.iv);
    expect(saved.authTag).toEqual(input.authTag);
    await expect(repository.countActiveByOwner(userId)).resolves.toBe(1);
  });

  it('counts only the ACTIVE rows of the owner it is asked about', async () => {
    const userId = await newUser();
    const otherId = await newUser();
    const first = document(userId);

    await repository.insert(first);
    await repository.insert(document(userId));
    await repository.insert(document(otherId));

    // UPDATE is granted to the runtime role, so a retained document can be retired.
    await prisma.identityDocument.update({
      where: { objectKey: first.objectKey },
      data: { status: 'DELETED', deletedAt: new Date() },
    });

    await expect(repository.countActiveByOwner(userId)).resolves.toBe(1);
    await expect(repository.countActiveByOwner(otherId)).resolves.toBe(1);
  });

  it('rejects a media type the ingest pipeline never produces', async () => {
    const userId = await newUser();

    await expect(
      prisma.identityDocument.create({
        data: { ...columns(document(userId)), contentType: 'application/pdf' },
      }),
    ).rejects.toThrow();

    await expect(repository.countActiveByOwner(userId)).resolves.toBe(0);
  });

  it('rejects an envelope that is not AES-256-GCM shaped', async () => {
    const userId = await newUser();

    for (const bad of [
      { iv: Buffer.alloc(16, 8) },
      { iv: Buffer.alloc(0) },
      { authTag: Buffer.alloc(12, 9) },
      { authTag: Buffer.alloc(20, 9) },
    ]) {
      await expect(
        prisma.identityDocument.create({ data: columns(document(userId, bad)) }),
      ).rejects.toThrow();
    }

    await expect(repository.countActiveByOwner(userId)).resolves.toBe(0);
  });

  it('rejects an empty document and a digest that is not lowercase hex', async () => {
    const userId = await newUser();

    for (const bad of [
      { sizeBytes: 0 },
      { sizeBytes: -1 },
      { sha256: 'A1'.repeat(32) },
      { sha256: 'a1'.repeat(31) },
      { sha256: `${'a1'.repeat(32)} ` },
    ]) {
      await expect(
        prisma.identityDocument.create({ data: columns(document(userId, bad)) }),
      ).rejects.toThrow();
    }

    await expect(repository.countActiveByOwner(userId)).resolves.toBe(0);
  });

  it('refuses a second row under the same object key', async () => {
    const userId = await newUser();
    const first = document(userId);

    await repository.insert(first);

    await expect(
      repository.insert(document(userId, { objectKey: first.objectKey })),
    ).rejects.toThrow();
    await expect(repository.countActiveByOwner(userId)).resolves.toBe(1);
  });

  it('does not let the runtime role delete a document', async () => {
    const userId = await newUser();
    const saved = await repository.insert(document(userId));

    const [privileges] = await prisma.$queryRaw<
      Array<{
        can_select: boolean;
        can_insert: boolean;
        can_update: boolean;
        can_delete: boolean;
      }>
    >`
      SELECT
        has_table_privilege(current_user, 'public.identity_document', 'SELECT') AS can_select,
        has_table_privilege(current_user, 'public.identity_document', 'INSERT') AS can_insert,
        has_table_privilege(current_user, 'public.identity_document', 'UPDATE') AS can_update,
        has_table_privilege(current_user, 'public.identity_document', 'DELETE') AS can_delete
    `;

    expect(privileges).toEqual({
      can_select: true,
      can_insert: true,
      can_update: true,
      can_delete: false,
    });

    await expect(prisma.identityDocument.delete({ where: { id: saved.id } })).rejects.toThrow(
      /permission denied/i,
    );
    await expect(repository.countActiveByOwner(userId)).resolves.toBe(1);
  });

  it('refuses to remove an account that still holds a document', async () => {
    const userId = await newUser();

    await repository.insert(document(userId));

    // RESTRICT, not CASCADE: the retention step decides what happens to the blob.
    await expect(prisma.user.delete({ where: { id: userId } })).rejects.toThrow(/foreign key/i);
    await expect(repository.countActiveByOwner(userId)).resolves.toBe(1);
  });
});
