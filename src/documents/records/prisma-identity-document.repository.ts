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

  async findActiveById(
    id: string,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // `status` is part of the filter, not a column the caller checks afterwards:
    // a deleted row can never be handed out by accident. The explicit `select`
    // also keeps the read to the envelope the decryption needs.
    const row = await client.identityDocument.findFirst({
      where: { id, status: 'ACTIVE' },
      select: RECORD_FIELDS,
    });

    return row === null ? null : toRecord(row);
  }

  async listActiveByOwner(
    ownerUserId: string,
    limit: number,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord[]> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // A total order (time, then the unique id) makes the answer stable between
    // two reads of the same rows. The cap is applied by the query, so a large
    // account cannot make the route read or serialize an unbounded set.
    const rows = await client.identityDocument.findMany({
      where: { ownerUserId, status: 'ACTIVE' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit,
      select: RECORD_FIELDS,
    });

    return rows.map(toRecord);
  }

  async softDeleteOwnedActive(
    documentId: string,
    ownerUserId: string,
    deletedAt: Date,
    tx?: Prisma.TransactionClient,
  ): Promise<IdentityDocumentRecord | null> {
    const client: Prisma.TransactionClient = tx ?? this.prisma;
    // Read first for the columns the trail names (kind, id), then write with the
    // same predicate. The UPDATE is the gate: `count` is 1 only for the caller
    // that moved an ACTIVE row, so a racing or repeated delete writes nothing.
    const where = { id: documentId, ownerUserId, status: 'ACTIVE' as const };
    const row = await client.identityDocument.findFirst({ where, select: RECORD_FIELDS });

    if (row === null) return null;

    const result = await client.identityDocument.updateMany({
      where,
      data: { status: 'DELETED', deletedAt },
    });

    return result.count === 1 ? toRecord({ ...row, status: 'DELETED', deletedAt }) : null;
  }
}
