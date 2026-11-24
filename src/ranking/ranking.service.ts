/**
 * Staff-entered competition results and the server-side ranking.
 *
 * The order is the policy:
 *
 *   1. the caller is a staff principal, guaranteed by the guards in front;
 *   2. the target athlete exists and their resume is APPROVED - a missing id,
 *      a pending one and a rejected one are the same generic 404;
 *   3. a staff member may not enter, correct or withdraw a result for their own
 *      athlete profile; that refusal is a 403 and says nothing about the row;
 *   4. the result change, the recompute and every audit row share one
 *      transaction, behind a transaction-level advisory lock, so concurrent
 *      changes serialize and a failure anywhere rolls the whole change back.
 *
 * No method accepts a score from the person the result belongs to: every input
 * is staff input, and `enteredById` is stamped from the verified token.
 */

import {
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { PrismaService } from '../database/prisma.service';
import { DEFAULT_RANKING_PAGE_SIZE } from './ranking.dto';
import {
  RANKING_REPOSITORY,
  type CompetitionResultRow,
  type CompetitionResultTarget,
  type RankingRepository,
  type RankingRow,
  type RankingTotal,
} from './ranking.repository';

/** The closed set of audit actions this feature writes. */
export const RANKING_AUDIT_ACTIONS = {
  RESULT_CREATED: 'ranking.result.created',
  RESULT_UPDATED: 'ranking.result.updated',
  RESULT_DELETED: 'ranking.result.deleted',
  RANK_CHANGED: 'ranking.rank.changed',
} as const;

export type RankingResultAction = 'created' | 'updated' | 'deleted';

/** The audit action of each result change, chosen once so no key is built. */
const RESULT_AUDIT_ACTIONS: Record<RankingResultAction, string> = {
  created: RANKING_AUDIT_ACTIONS.RESULT_CREATED,
  updated: RANKING_AUDIT_ACTIONS.RESULT_UPDATED,
  deleted: RANKING_AUDIT_ACTIONS.RESULT_DELETED,
};

const RESULT_TARGET_TYPE = 'competition_result';
const RANKING_TARGET_TYPE = 'athlete_ranking';

/** Two staff changes wait for each other rather than compute a half ranking. */
const TRANSACTION_OPTIONS = { maxWait: 5_000, timeout: 10_000 } as const;

export interface CreateCompetitionResultInput {
  readonly athleteProfileId: string;
  readonly eventName: string;
  readonly eventDate: Date;
  readonly points: number;
}

export interface UpdateCompetitionResultInput {
  readonly eventName?: string;
  readonly eventDate?: Date;
  readonly points?: number;
}

export interface ListRankingResultsInput {
  readonly athleteProfileId?: string;
  readonly limit?: number;
  readonly cursor?: string;
}

/** One result, exactly as it leaves the API. `eventDate` is a plain date. */
export interface CompetitionResultView {
  readonly id: string;
  readonly athleteProfileId: string;
  readonly eventName: string;
  readonly eventDate: string;
  readonly points: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CompetitionResultPage {
  readonly items: CompetitionResultView[];
  /** `null` on the last page; otherwise the id to pass back as `cursor`. */
  readonly nextCursor: string | null;
}

/** What one athlete's ranking changed from and to inside one recompute. */
export interface RankChange {
  readonly athleteProfileId: string;
  readonly oldPoints: number;
  readonly newPoints: number;
  readonly oldRank: number | null;
  readonly newRank: number | null;
}

/**
 * Competition ranking: equal totals share a rank and the next distinct total
 * takes the position after the tie (1, 2, 2, 4). Ties are ordered by profile id
 * only so two runs produce the same upsert order; the rank itself never depends
 * on it.
 */
export function assignCompetitionRanks(totals: readonly RankingTotal[]): RankingRow[] {
  const sorted = [...totals].sort(
    (left, right) =>
      right.totalPoints - left.totalPoints ||
      left.athleteProfileId.localeCompare(right.athleteProfileId),
  );

  const ranked: RankingRow[] = [];
  let rank = 0;
  let previousTotal: number | null = null;

  sorted.forEach((row, index) => {
    if (row.totalPoints !== previousTotal) {
      rank = index + 1;
      previousTotal = row.totalPoints;
    }

    ranked.push({ athleteProfileId: row.athleteProfileId, totalPoints: row.totalPoints, rank });
  });

  return ranked;
}

function toView(row: CompetitionResultRow): CompetitionResultView {
  return {
    id: row.id,
    athleteProfileId: row.athleteProfileId,
    eventName: row.eventName,
    eventDate: row.eventDate.toISOString().slice(0, 10),
    points: row.points,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

@Injectable()
export class RankingService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(RANKING_REPOSITORY) private readonly repository: RankingRepository,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /** Records one staff-entered result and recomputes the ranking atomically. */
  async createResult(
    actor: PolicySubject,
    input: CreateCompetitionResultInput,
    context: AccessPolicyContext,
  ): Promise<CompetitionResultView> {
    const profile = await this.repository.findProfile(input.athleteProfileId);

    // A missing profile and a not-yet-approved one are the same generic 404.
    if (profile === null || profile.reviewStatus !== 'APPROVED') throw new NotFoundException();

    this.refuseOwnProfile(actor, profile.userId, context.requestId, 'entry');

    let created!: CompetitionResultRow;

    await this.prisma.$transaction(async (tx) => {
      created = await this.repository.createResult(
        {
          athleteProfileId: profile.id,
          eventName: input.eventName,
          eventDate: input.eventDate,
          points: input.points,
          enteredById: actor.id,
        },
        tx,
      );

      const changes = await this.recompute(tx);

      await this.recordResultChange(
        'created',
        actor,
        created.id,
        profile.id,
        null,
        input.points,
        input.eventName,
        context,
        tx,
      );

      await this.recordRankChanges(actor, changes, context, tx);
    }, TRANSACTION_OPTIONS);

    return toView(created);
  }

  /** Corrects points, event name or date, then recomputes in the same transaction. */
  async updateResult(
    actor: PolicySubject,
    resultId: string,
    input: UpdateCompetitionResultInput,
    context: AccessPolicyContext,
  ): Promise<CompetitionResultView> {
    const target = await this.target(resultId);

    this.refuseOwnProfile(actor, target.ownerUserId, context.requestId, 'correction');

    // A ranking only exists for an approved resume, so a correction for a
    // non-approved athlete is the same generic 404 as an entry.
    if (target.reviewStatus !== 'APPROVED') throw new NotFoundException();

    const points = input.points ?? target.points;
    const eventName = input.eventName ?? target.eventName;

    await this.prisma.$transaction(async (tx) => {
      const changed = await this.repository.updateResult(resultId, input, tx);

      // The row disappeared between the read above and this statement: nothing
      // is written, and the rollback keeps it so.
      if (changed !== 1) throw new NotFoundException();

      const changes = await this.recompute(tx);

      await this.recordResultChange(
        'updated',
        actor,
        resultId,
        target.athleteProfileId,
        target.points,
        points,
        eventName,
        context,
        tx,
      );

      await this.recordRankChanges(actor, changes, context, tx);
    }, TRANSACTION_OPTIONS);

    const updated = await this.repository.findResult(resultId);

    if (updated === null) throw new NotFoundException();

    return toView(updated);
  }

  /**
   * Withdraws one result and recomputes. Deliberately allowed even when the
   * athlete's resume is no longer APPROVED: a rejected athlete's old rows must
   * still be removable, and such a row is not on the leaderboard anyway.
   */
  async deleteResult(
    actor: PolicySubject,
    resultId: string,
    context: AccessPolicyContext,
  ): Promise<void> {
    const target = await this.target(resultId);

    this.refuseOwnProfile(actor, target.ownerUserId, context.requestId, 'withdrawal');

    await this.prisma.$transaction(async (tx) => {
      const deleted = await this.repository.deleteResult(resultId, tx);

      if (deleted !== 1) throw new NotFoundException();

      const changes = await this.recompute(tx);

      await this.recordResultChange(
        'deleted',
        actor,
        resultId,
        target.athleteProfileId,
        target.points,
        null,
        target.eventName,
        context,
        tx,
      );

      await this.recordRankChanges(actor, changes, context, tx);
    }, TRANSACTION_OPTIONS);
  }

  /** One page of stored results, newest event first. */
  async listResults(query: ListRankingResultsInput): Promise<CompetitionResultPage> {
    const limit = query.limit ?? DEFAULT_RANKING_PAGE_SIZE;
    const rows = await this.repository.listResults(query.athleteProfileId, limit, query.cursor);
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];

    return {
      items: page.map(toView),
      nextCursor: rows.length > limit && last !== undefined ? last.id : null,
    };
  }

  /**
   * Recomputes every ranking row from the approved athletes' totals.
   *
   * The advisory lock is taken before the first read, so two concurrent staff
   * changes cannot each compute from the other's half-written state. Rows whose
   * total or rank did not change are not rewritten and produce no audit row;
   * rows of athletes without results are removed.
   */
  private async recompute(tx: Prisma.TransactionClient): Promise<RankChange[]> {
    await this.repository.lock(tx);

    const totals = await this.repository.sumApprovedTotals(tx);
    const ranked = assignCompetitionRanks(totals);
    const current = await this.repository.listRankings(tx);
    const existing = new Map(current.map((row) => [row.athleteProfileId, row]));
    const changes: RankChange[] = [];

    for (const row of ranked) {
      const previous = existing.get(row.athleteProfileId);

      if (
        previous !== undefined &&
        previous.totalPoints === row.totalPoints &&
        previous.rank === row.rank
      ) {
        continue;
      }

      await this.repository.upsertRanking(row, tx);

      changes.push({
        athleteProfileId: row.athleteProfileId,
        oldPoints: previous?.totalPoints ?? 0,
        newPoints: row.totalPoints,
        oldRank: previous?.rank ?? null,
        newRank: row.rank,
      });
    }

    const rankedIds = new Set(ranked.map((row) => row.athleteProfileId));

    for (const row of current) {
      if (rankedIds.has(row.athleteProfileId)) continue;

      await this.repository.deleteRanking(row.athleteProfileId, tx);

      changes.push({
        athleteProfileId: row.athleteProfileId,
        oldPoints: row.totalPoints,
        newPoints: 0,
        oldRank: row.rank,
        newRank: null,
      });
    }

    return changes;
  }

  /** One result by id, or the generic 404; never any detail in the refusal. */
  private async target(resultId: string): Promise<CompetitionResultTarget> {
    const target = await this.repository.findResult(resultId);

    if (target === null) throw new NotFoundException();

    return target;
  }

  /**
   * A staff member with an athlete profile of their own cannot score it. The
   * refusal is a 403 on purpose: the staff member already knows the profile is
   * theirs, and the message still carries no ids.
   */
  private refuseOwnProfile(
    actor: PolicySubject,
    ownerUserId: string,
    requestId: string | undefined,
    attempt: string,
  ): void {
    if (ownerUserId !== actor.id) return;

    this.logger.warn(
      { requestId, action: 'ranking.own_profile_refused' },
      `staff ranking refused: own profile ${attempt}`,
    );

    throw new ForbiddenException();
  }

  /**
   * Fail closed: the trail and the change share one transaction, so a trail that
   * cannot be written rolls the change back rather than report a result nobody
   * can account for.
   */
  private async recordResultChange(
    action: RankingResultAction,
    actor: PolicySubject,
    resultId: string,
    athleteProfileId: string,
    oldPoints: number | null,
    newPoints: number | null,
    eventName: string,
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    const auditAction = RESULT_AUDIT_ACTIONS[action];

    try {
      await this.audit.record(
        {
          action: auditAction,
          actorId: actor.id,
          actorRole: String(actor.role),
          targetType: RESULT_TARGET_TYPE,
          targetId: resultId,
          requestId: context.requestId,
          ip: context.ip,
          metadata: { resultId, athleteProfileId, oldPoints, newPoints, eventName },
        },
        tx,
      );
    } catch {
      this.logger.warn(
        { requestId: context.requestId, action: auditAction },
        'staff ranking audit failed',
      );

      throw new ServiceUnavailableException();
    }
  }

  /** One row per athlete whose total or rank the recompute changed. */
  private async recordRankChanges(
    actor: PolicySubject,
    changes: readonly RankChange[],
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    try {
      for (const change of changes) {
        await this.audit.record(
          {
            action: RANKING_AUDIT_ACTIONS.RANK_CHANGED,
            actorId: actor.id,
            actorRole: String(actor.role),
            targetType: RANKING_TARGET_TYPE,
            targetId: change.athleteProfileId,
            requestId: context.requestId,
            ip: context.ip,
            metadata: {
              athleteProfileId: change.athleteProfileId,
              oldPoints: change.oldPoints,
              newPoints: change.newPoints,
              oldRank: change.oldRank,
              newRank: change.newRank,
            },
          },
          tx,
        );
      }
    } catch {
      this.logger.warn(
        { requestId: context.requestId, action: RANKING_AUDIT_ACTIONS.RANK_CHANGED },
        'staff ranking audit failed',
      );

      throw new ServiceUnavailableException();
    }
  }
}
