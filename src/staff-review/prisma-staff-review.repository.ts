import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import type { DocumentKind } from '../documents/records/identity-document.repository';
import {
  type ReviewDocumentMetadata,
  type ReviewRecipient,
  type StaffReviewRepository,
} from './staff-review.repository';

/** Metadata columns only: the storage object key never reaches this query. */
const DOCUMENT_FIELDS = {
  id: true,
  kind: true,
  sizeBytes: true,
  createdAt: true,
} as const;

interface DocumentRow {
  readonly id: string;
  readonly kind: DocumentKind;
  readonly sizeBytes: number;
  readonly createdAt: Date;
}

@Injectable()
export class PrismaStaffReviewRepository implements StaffReviewRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** One grouped query for the whole page; owners without ACTIVE rows are absent. */
  async countActiveDocuments(
    ownerUserIds: readonly string[],
  ): Promise<ReadonlyMap<string, number>> {
    if (ownerUserIds.length === 0) return new Map();

    const rows = await this.prisma.identityDocument.groupBy({
      by: ['ownerUserId'],
      where: { ownerUserId: { in: [...ownerUserIds] }, status: 'ACTIVE' },
      _count: { _all: true },
    });

    return new Map(rows.map((row) => [row.ownerUserId, row._count._all]));
  }

  async listActiveDocuments(ownerUserId: string): Promise<ReviewDocumentMetadata[]> {
    const rows: DocumentRow[] = await this.prisma.identityDocument.findMany({
      where: { ownerUserId, status: 'ACTIVE' },
      orderBy: [{ createdAt: 'desc' }, { id: 'asc' }],
      select: DOCUMENT_FIELDS,
    });

    return rows;
  }

  /** The owner's address only; `null` when the profile row is gone. */
  async findRecipient(profileId: string): Promise<ReviewRecipient | null> {
    const row = await this.prisma.athleteProfile.findUnique({
      where: { userId: profileId },
      select: { user: { select: { email: true } } },
    });

    return row === null ? null : { email: row.user.email };
  }
}
