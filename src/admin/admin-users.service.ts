import { createHash } from 'node:crypto';
import {
  ForbiddenException,
  Inject,
  Optional,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import { AccessAction, type PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import { isStaffRole, Role } from '../auth/roles';
import {
  SESSION_REPOSITORY,
  type AdminUserListPage,
  type SessionRepository,
} from '../auth/session.repository';
import { TOTP_REPOSITORY, type TotpRepository } from '../auth/totp/totp.repository';
import { isUuid } from '../common/middleware/request-id.middleware';
import { PrismaService } from '../database/prisma.service';
import { DangerousActionsService } from '../dangerous-actions/dangerous-actions.service';
import type { AdminUsersFilter } from './admin-users.dto';
import { OWNER_NOTIFIER, type OwnerNotifier } from './owner-notifier';

/** Audit names for the actions this module performs; the set is closed. */
export const ADMIN_AUDIT_ACTIONS = {
  USER_BLOCK: 'admin.user.block',
  USER_UNBLOCK: 'admin.user.unblock',
  ADMIN_GRANT: 'admin.admin.grant',
  ADMIN_REVOKE: 'admin.admin.revoke',
  TOTP_RESET: 'admin.totp.reset',
  /** The only read in the set: it records who looked, not what changed. */
  USERS_LIST: 'admin.users.list',
} as const;

export type AdminAuditAction = (typeof ADMIN_AUDIT_ACTIONS)[keyof typeof ADMIN_AUDIT_ACTIONS];

/**
 * One row of `GET /admin/users`: an allowlist, and no hash, phone or
 * second-factor state ever crosses it.
 */
export interface AdminUserView {
  readonly id: string;
  readonly username: string;
  readonly email: string | null;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'BLOCKED';
  readonly createdAt: string;
}

export interface AdminUsersPageView {
  readonly users: readonly AdminUserView[];
  readonly page: number;
  readonly pageSize: number;
  readonly total: number;
}

/** A target read from storage; a request body can never supply these values. */
export interface AdminTarget {
  readonly id: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'BLOCKED';
}

export type LoadTargetResult =
  { readonly found: true; readonly target: AdminTarget } | { readonly found: false };

export type AdminAuthorization = { readonly allowed: true } | { readonly allowed: false };

/** Shared values, so no caller can tell two refusals apart. */
const ALLOWED: AdminAuthorization = Object.freeze({ allowed: true });
const REFUSED: AdminAuthorization = Object.freeze({ allowed: false });
const TARGET_NOT_FOUND: LoadTargetResult = Object.freeze({ found: false });

const AUDIT_TARGET_TYPE = 'user';
const REVOCATION_REASON = 'admin_action';

/**
 * A search term reaches the trail as a hash: the trail never carries the
 * address itself, only the fact that somebody searched for one and which.
 */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Shared helpers for the administrative user endpoints, plus the state
 * transitions they own: block, unblock, the admin grant, the admin revoke and
 * the second-factor reset.
 */
@Injectable()
export class AdminUsersService {
  constructor(
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    @Inject(TOTP_REPOSITORY) private readonly totp: TotpRepository,
    private readonly policy: AccessPolicyService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
    @Inject(OWNER_NOTIFIER) private readonly notifier: OwnerNotifier,
    // The moderation rows and their audit trail share one transaction.
    private readonly prisma: PrismaService,
    @Optional() private readonly dangerous?: DangerousActionsService,
  ) {}

  /**
   * A malformed id cannot own a row, so it answers exactly like an unknown one:
   * the same value, not merely the same shape.
   */
  async loadTarget(id: string): Promise<LoadTargetResult> {
    if (!isUuid(id)) return TARGET_NOT_FOUND;

    const target = await this.sessions.findUserById(id);

    return target === null ? TARGET_NOT_FOUND : { found: true, target };
  }

  /**
   * The actor comes from the verified principal and the target from storage;
   * a role or a flag in the request body never reaches the policy.
   */
  authorize(
    action: AccessAction,
    actor: PolicySubject,
    target: PolicySubject | null,
  ): AdminAuthorization {
    if (target === null) return REFUSED;

    return this.policy.decide(actor, { action }, target).allowed ? ALLOWED : REFUSED;
  }

  /**
   * One page of accounts, oldest first. There is no target row, so the policy
   * is not asked: the staff role is the whole rule, and the route's markers
   * already say so - the check here is the belt to those braces.
   *
   * The response is built from the allowlist and nothing else: the repository
   * never reads a hash, a phone number or the second-factor state, so no later
   * edit to the query can leak one into the page.
   */
  async list(
    actor: PolicySubject,
    filter: AdminUsersFilter,
    requestId: string,
  ): Promise<AdminUsersPageView> {
    if (!isStaffRole(actor.role)) throw new ForbiddenException();

    const page = await this.sessions.listAccounts(filter);

    await this.recordListAudit(actor, filter, page, requestId);

    return {
      users: page.rows.map((row) => ({
        id: row.id,
        username: row.username,
        email: row.email,
        role: row.role,
        status: row.status,
        createdAt: row.createdAt.toISOString(),
      })),
      page: filter.page,
      pageSize: filter.pageSize,
      total: page.total,
    };
  }

  /**
   * One trail row per listing: who asked, what narrowed the page and how much
   * it held. Fail closed like the detail read in the review queue - a listing
   * nobody can account for is not served.
   */
  private async recordListAudit(
    actor: PolicySubject,
    filter: AdminUsersFilter,
    page: AdminUserListPage,
    requestId: string,
  ): Promise<void> {
    const action = ADMIN_AUDIT_ACTIONS.USERS_LIST;

    try {
      await this.audit.record({
        action,
        actorId: actor.id,
        actorRole: String(actor.role),
        requestId,
        metadata: {
          page: filter.page,
          pageSize: filter.pageSize,
          role: filter.role ?? null,
          blocked: filter.blocked ?? null,
          addressFilterSha256: filter.email === undefined ? null : sha256Hex(filter.email),
          results: page.rows.length,
          total: page.total,
        },
      });
    } catch {
      this.logger.warn({ requestId, action }, 'admin audit failed');

      throw new ServiceUnavailableException();
    }
  }

  /**
   * Block: revoke first, then block and record in one transaction.
   *
   * The revocation runs before the state change and even when the account was
   * already blocked, so a retry finishes a revocation that failed earlier: a
   * blocked account whose sessions still work is exactly the state this
   * endpoint exists to prevent. A revocation that fails therefore leaves the
   * account as it was and records nothing - the action did not happen.
   *
   * The compare-and-set and its audit row share one transaction, so a trail
   * that cannot be written rolls the block back. The required `reason` is part
   * of that row and of nothing else: no response, log or message carries it.
   */
  async block(actor: PolicySubject, id: string, requestId: string, reason: string): Promise<void> {
    const target = await this.permittedTarget(AccessAction.USER_BLOCK, actor, id);

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.USER_BLOCK },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    await this.prisma.$transaction(async (tx) => {
      const changed = await this.sessions.setStatusIf(target.id, 'ACTIVE', 'BLOCKED', tx);

      // An account that was already blocked has nothing new to record.
      if (!changed) return;

      await this.recordSuccess(
        ADMIN_AUDIT_ACTIONS.USER_BLOCK,
        actor.id,
        target.id,
        requestId,
        { targetUserId: target.id, reason },
        tx,
      );
    });
  }

  /**
   * Unblock: the account can sign in again, the sessions it lost stay lost, and
   * the transition joins its audit row in one transaction like the block does.
   */
  async unblock(
    actor: PolicySubject,
    id: string,
    requestId: string,
    reason: string,
  ): Promise<void> {
    const target = await this.permittedTarget(AccessAction.USER_UNBLOCK, actor, id);

    await this.prisma.$transaction(async (tx) => {
      const changed = await this.sessions.setStatusIf(target.id, 'BLOCKED', 'ACTIVE', tx);

      if (!changed) return;

      await this.recordSuccess(
        ADMIN_AUDIT_ACTIONS.USER_UNBLOCK,
        actor.id,
        target.id,
        requestId,
        { targetUserId: target.id, reason },
        tx,
      );
    });
  }

  /**
   * Grant admin: revoke first, then promote and record in one transaction.
   *
   * The order carries the guarantees. The revocation runs before the role change
   * and even for a target that is already an admin, so a retry finishes a
   * revocation that failed earlier: a promoted account whose old sessions work
   * is the state this endpoint exists to prevent. A revocation that fails
   * therefore leaves the role as it was and records nothing.
   *
   * The compare-and-set and its audit row share one transaction, so a trail that
   * cannot be written rolls the promotion back. The owner is told only after
   * that transaction commits, so a rolled-back grant is never announced.
   *
   * A retry after an interrupted grant finds the target already an admin: it
   * still revokes and records nothing, exactly like a repeated block.
   */
  async grantAdmin(actor: PolicySubject, id: string, requestId: string): Promise<any> {
    const target = await this.grantTarget(actor, id);
    if (actor.role !== Role.OWNER && this.dangerous !== undefined)
      return this.dangerous.runOrQueue(
        actor,
        'ADMIN_GRANT',
        { targetId: target.id, role: Role.ADMIN },
        () => this.grantAdminNow(actor, id, requestId),
      );
    return this.grantAdminNow(actor, id, requestId);
  }

  /** Executes an already-approved grant without entering the dangerous-action queue. */
  async executeGrantAdmin(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    return this.grantAdminNow(actor, id, requestId);
  }

  private async grantAdminNow(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.grantTarget(actor, id);

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      // Same rule as block: the role change has not run yet, so nothing changed
      // and nothing was recorded; the next attempt retries both steps.
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.ADMIN_GRANT },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    const granted = await this.prisma.$transaction(async (tx) => {
      if (!(await this.promote(target, tx))) return false;

      await this.recordSuccess(
        ADMIN_AUDIT_ACTIONS.ADMIN_GRANT,
        actor.id,
        target.id,
        requestId,
        {
          from: target.role,
          to: Role.ADMIN,
          // The notice is sent once this row commits; a delivery failure is
          // logged and leaves the grant in place.
          notified: true,
        },
        tx,
      );

      return true;
    });

    // Never for a rolled-back change: there is no privilege to announce.
    if (!granted) return;

    await this.notifyOwner(actor.id, target.id, requestId);
  }

  /**
   * Revoke admin: revoke first, then demote and record in one transaction.
   *
   * Only an account that is an admin right now can be demoted. An id that owns
   * no row, an id that is not a uuid and an account holding any other role all
   * leave through the same generic 403, so the endpoint never states which ids
   * exist or what they hold.
   *
   * The revocation comes before the demotion, so a failed revocation changes
   * nothing. The compare-and-set and its audit row share one transaction: a
   * trail that cannot be written rolls the demotion back. A lost compare-and-set
   * means a parallel revoke demoted the target first; the revocation was still
   * ours to finish, and nothing is recorded for it. The second factor is a
   * separate permission and is left untouched: the demotion changes the role and
   * nothing else.
   */
  async revokeAdmin(actor: PolicySubject, id: string, requestId: string): Promise<any> {
    const target = await this.adminOnlyTarget(actor, id, AccessAction.ADMIN_REVOKE);
    if (actor.role !== Role.OWNER && this.dangerous !== undefined)
      return this.dangerous.runOrQueue(
        actor,
        'ADMIN_REVOKE',
        { targetId: target.id, role: Role.USER },
        () => this.revokeAdminNow(actor, id, requestId),
      );
    return this.revokeAdminNow(actor, id, requestId);
  }

  /** Executes an already-approved revoke without entering the dangerous-action queue. */
  async executeRevokeAdmin(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    return this.revokeAdminNow(actor, id, requestId);
  }

  private async revokeAdminNow(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.adminOnlyTarget(actor, id, AccessAction.ADMIN_REVOKE);

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      // Same rule as block: the demotion has not run yet, so nothing changed and
      // nothing was recorded; the next attempt retries both steps.
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.ADMIN_REVOKE },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    await this.prisma.$transaction(async (tx) => {
      if (!(await this.demote(target, tx))) return;

      await this.recordSuccess(
        ADMIN_AUDIT_ACTIONS.ADMIN_REVOKE,
        actor.id,
        target.id,
        requestId,
        { from: Role.ADMIN, to: Role.USER },
        tx,
      );
    });
  }

  /**
   * Second-factor reset: revoke first, then delete and record in one
   * transaction.
   *
   * The credential, its recovery codes and the audit row share one transaction,
   * so a trail that cannot be written restores the factor. The revocation runs
   * before that removal and even when nothing was left to delete, so a retry
   * after a failed revocation finishes it; a failed revocation therefore changes
   * nothing. Only a call that actually removed something is recorded, exactly
   * like a repeated block. The role stays ADMIN: the staff gate keeps the account
   * on the second-factor routes until it enrolls again.
   */
  async resetTotp(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.adminOnlyTarget(actor, id, AccessAction.TOTP_RESET);

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      // Same rule as the other actions: nothing was removed and nothing was
      // recorded; the next attempt retries both steps.
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.TOTP_RESET },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    await this.prisma.$transaction(async (tx) => {
      if (!(await this.totp.deleteCredential(target.id, tx))) return;

      await this.recordSuccess(
        ADMIN_AUDIT_ACTIONS.TOTP_RESET,
        actor.id,
        target.id,
        requestId,
        { role: Role.ADMIN },
        tx,
      );
    });
  }

  /**
   * Target and permission together, so no endpoint can act before deciding.
   *
   * A malformed id owns no row either, so it answers exactly like an unknown
   * one, and every refusal is the same generic 403: the reason never reaches the
   * client and no denial row is added here.
   */
  private async permittedTarget(
    action: AccessAction,
    actor: PolicySubject,
    id: string,
  ): Promise<AdminTarget> {
    const loaded = await this.loadTarget(id);

    if (!loaded.found) throw new NotFoundException();

    const target: PolicySubject = { id: loaded.target.id, role: loaded.target.role };

    if (!this.authorize(action, actor, target).allowed) throw new ForbiddenException();

    return loaded.target;
  }

  /**
   * Who may be promoted, and by whom.
   *
   * The policy answers the permission half. It also refuses a target that is
   * already an admin, which is the retry case and not a permission problem:
   * that one reason is the only refusal this path lets through, and an ADMIN
   * actor never reaches it because the actor rule runs first. Everything else,
   * including a blocked target, is the same generic 403 as every other refusal.
   */
  private async grantTarget(actor: PolicySubject, id: string): Promise<AdminTarget> {
    const loaded = await this.loadTarget(id);

    if (!loaded.found) throw new NotFoundException();

    // Only a live account can take on staff duties; why it is not live stays here.
    if (loaded.target.status !== 'ACTIVE') throw new ForbiddenException();

    const decision = this.policy.decide(
      actor,
      { action: AccessAction.ADMIN_GRANT },
      { id: loaded.target.id, role: loaded.target.role },
    );

    if (decision.allowed || decision.reason === 'target_already_admin') return loaded.target;

    throw new ForbiddenException();
  }

  /**
   * The compare-and-set owns the transition and the stored role is the only
   * expectation accepted, so a request body cannot choose the starting point.
   * False means the target is already an admin and there is nothing to record.
   *
   * A caller-owned `tx` makes the role change join that transaction, so it
   * commits or rolls back with the audit row that describes it.
   */
  private async promote(target: AdminTarget, tx?: Prisma.TransactionClient): Promise<boolean> {
    if (target.role === Role.ADMIN) return false;

    if (await this.sessions.setRoleIf(target.id, target.role, Role.ADMIN, tx)) return true;

    // Lost a race: only a concurrent grant of the same privilege is acceptable.
    const current = await this.loadTarget(target.id);

    if (current.found && current.target.role === Role.ADMIN) return false;

    throw new ForbiddenException();
  }

  /**
   * Who may be demoted or lose a factor, and by whom.
   *
   * The target has to be an admin as storage reports it right now, and every
   * other answer is the same generic 403: an unknown id, a malformed id and an
   * account that never held the role cannot be told apart, so nothing here says
   * which ids exist. The policy then answers the permission half, with the same
   * refusal for an admin actor, for oneself and for the owner row.
   */
  private async adminOnlyTarget(
    actor: PolicySubject,
    id: string,
    action: AccessAction.ADMIN_REVOKE | AccessAction.TOTP_RESET,
  ): Promise<AdminTarget> {
    const loaded = await this.loadTarget(id);

    if (!loaded.found) throw new ForbiddenException();
    if (loaded.target.role !== Role.ADMIN) throw new ForbiddenException();

    const decision = this.policy.decide(
      actor,
      { action },
      { id: loaded.target.id, role: loaded.target.role },
    );

    if (!decision.allowed) throw new ForbiddenException();

    return loaded.target;
  }

  /**
   * The demotion itself: one compare-and-set from the stored role, so a request
   * body cannot choose the starting point and two revokes cannot both count as
   * the change. False means another revoke got there first.
   *
   * A caller-owned `tx` makes the role change join that transaction, so it
   * commits or rolls back with the audit row that describes it.
   */
  private async demote(target: AdminTarget, tx?: Prisma.TransactionClient): Promise<boolean> {
    if (await this.sessions.setRoleIf(target.id, Role.ADMIN, Role.USER, tx)) return true;

    // Lost the race: a demoted target is the only acceptable outcome here.
    const current = await this.loadTarget(target.id);

    if (current.found && current.target.role === Role.USER) return false;

    throw new ForbiddenException();
  }

  /**
   * Best effort by contract: the grant already committed, so a failed delivery
   * is logged without ids and never undoes the privilege.
   */
  private async notifyOwner(
    actorId: string,
    targetId: string,
    requestId: string,
  ): Promise<boolean> {
    try {
      await this.notifier.notifyAdminGranted({ actorId, targetId, at: new Date() });

      return true;
    } catch {
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.ADMIN_GRANT },
        'owner notify failed',
      );

      return false;
    }
  }

  /**
   * No catch: a caller that ignored the failure would block an account whose
   * sessions still work, and report success for a revocation that never ran.
   */
  async revokeAllSessionsOrFail(targetId: string): Promise<void> {
    await this.sessions.revokeAllUserSessions(targetId, REVOCATION_REASON, new Date());
  }

  /**
   * Fail closed: an action that cannot be recorded did not happen. This is the
   * rule the required OTP audits already follow, so the caller must not report
   * success after this throws.
   *
   * A caller that owns a transaction passes it as `tx`, so the row joins the
   * change it describes and a failure rolls that change back with it.
   */
  async recordSuccess(
    action: AdminAuditAction,
    actorId: string,
    targetId: string,
    requestId: string,
    extraMeta: Record<string, unknown> = {},
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    try {
      await this.audit.record(
        {
          action,
          actorId,
          targetType: AUDIT_TARGET_TYPE,
          targetId,
          requestId,
          // Callers pass counts, roles and moderation reasons at most: never a
          // phone number or a name.
          metadata: extraMeta,
        },
        tx,
      );
    } catch {
      this.logger.warn({ requestId, action }, 'admin audit failed');

      throw new ServiceUnavailableException();
    }
  }
}
