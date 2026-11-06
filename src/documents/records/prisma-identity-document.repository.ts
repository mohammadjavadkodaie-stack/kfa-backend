import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../database/prisma.service';
import type {
  IdentityDocumentInsert,
  IdentityDocumentRecord,
  IdentityDocumentRepository,
} from './identity-document.repository';

/** Columns the repository reads back; nothing is hidden behind a `select *`. */
const RECORD_FIELDS = {
  id: true,
  ownerUserId: true,
  kind: true,
  objectKey: true,
  contentType: true,
  sizeBytes: true,
  sha256: true,
  keyId: true,
  wrappedDek: true,
  iv: true,
  authTag: true,
  status: true,
  createdAt: true,
  deletedAt: true,
} as const;

type DocumentRow = Prisma.IdentityDocumentGetPayload<{ select: typeof RECORD_FIELDS }>;

function toColumns(record: IdentityDocumentInsert) {
  return {
    ownerUserId: record.ownerUserId,
    kind: record.kind,
    objectKey: record.objectKey,
    contentType: record.contentType,
    sizeBytes: record.sizeBytes,
    sha256: record.sha256,
    keyId: record.keyId,
    // `Bytes` columns take a plain Uint8Array; a copy also keeps the caller's
    // buffer from being aliased by the client.
    wrappedDek: new Uint8Array(record.wrappedDek),
    iv: new Uint8Array(record.iv),
    authTag: new Uint8Array(record.authTag),
  };
}

/** `Bytes` columns come back as `Uint8Array`; the boundary hands out Buffers. */
function toRecord(row: DocumentRow): IdentityDocumentRecord {
  return {
    id: row.id,
    ownerUserId: row.ownerUserId,
    kind: row.kind,
    objectKey: row.objectKey,
    contentType: row.contentType as IdentityDocumentRecord['contentType'],
    sizeBytes: row.sizeBytes,
    sha256: row.sha256,
    keyId: row.keyId,
    wrappedDek: Buffer.from(row.wrappedDek),
    iv: Buffer.from(row.iv),
    authTag: Buffer.from(row.authTag),
    status: row.status,
    createdAt: row.createdAt,
    deletedAt: row.deletedAt,
  };
}

@Injectable()
export class PrismaIdentityDocumentRepository implements IdentityDocumentRepository {
  constructor(private readonly prisma: PrismaService) {}

  async insert(
    record: IdentityDocumentInsert,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord> {
    // The caller's transaction when there is one: only the shared client lets
    // the row roll back together with the audit entry that describes it.
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    const row = await client.identityDocument.create({
      data: toColumns(record),
      select: RECORD_FIELDS,
    });

    return toRecord(row);
  }

  async countActiveByOwner(ownerUserId: string, tx?: Prisma.TransactionClient): Promise<number> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;

    return client.identityDocument.count({ where: { ownerUserId, status: 'ACTIVE' } });
  }
}
