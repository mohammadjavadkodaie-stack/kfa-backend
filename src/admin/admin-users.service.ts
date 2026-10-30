import {
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import { AccessAction, type PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import { Role } from '../auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../auth/session.repository';
import { isUuid } from '../common/middleware/request-id.middleware';
import { OWNER_NOTIFIER, type OwnerNotifier } from './owner-notifier';

/** Audit names for the actions this module performs; the set is closed. */
export const ADMIN_AUDIT_ACTIONS = {
  USER_BLOCK: 'admin.user.block',
  USER_UNBLOCK: 'admin.user.unblock',
  ADMIN_GRANT: 'admin.admin.grant',
  ADMIN_REVOKE: 'admin.admin.revoke',
} as const;

export type AdminAuditAction = (typeof ADMIN_AUDIT_ACTIONS)[keyof typeof ADMIN_AUDIT_ACTIONS];

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
 * Shared helpers for the administrative user endpoints, plus the state
 * transitions they own: block, unblock and the admin grant.
 */
@Injectable()
export class AdminUsersService {
  constructor(
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    private readonly policy: AccessPolicyService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
    @Inject(OWNER_NOTIFIER) private readonly notifier: OwnerNotifier,
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
   * Block: block first, revoke second, record third.
   *
   * The revocation runs even when the account was already blocked, so a retry
   * finishes a revocation that failed earlier: a blocked account whose sessions
   * still work is exactly the state this endpoint exists to prevent.
   */
  async block(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.permittedTarget(AccessAction.USER_BLOCK, actor, id);

    const changed = await this.sessions.setStatusIf(target.id, 'ACTIVE', 'BLOCKED');

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      // The block is not rolled back: a retry repeats the revocation. Nothing
      // is recorded, so the log cannot show a block that left a session open.
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.USER_BLOCK },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    // An account that was already blocked has nothing new to record.
    if (!changed) return;

    await this.recordSuccess(ADMIN_AUDIT_ACTIONS.USER_BLOCK, actor.id, target.id, requestId, {
      from: 'ACTIVE',
      to: 'BLOCKED',
    });
  }

  /**
   * Unblock: the account can sign in again, the sessions it lost stay lost.
   */
  async unblock(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.permittedTarget(AccessAction.USER_UNBLOCK, actor, id);

    const changed = await this.sessions.setStatusIf(target.id, 'BLOCKED', 'ACTIVE');

    if (!changed) return;

    await this.recordSuccess(ADMIN_AUDIT_ACTIONS.USER_UNBLOCK, actor.id, target.id, requestId, {
      from: 'BLOCKED',
      to: 'ACTIVE',
    });
  }

  /**
   * Grant admin: role first, revoke second, notify third, record last.
   *
   * The order carries the guarantees. The new role only applies to a session
   * created after the revocation, and the row is written after the delivery
   * attempt so its metadata can state whether the owner was actually told.
   *
   * A retry after an interrupted grant finds the target already an admin: it
   * still revokes (a promoted account whose old sessions work is the state this
   * endpoint exists to prevent) and records nothing, exactly like a repeated
   * block.
   */
  async grantAdmin(actor: PolicySubject, id: string, requestId: string): Promise<void> {
    const target = await this.grantTarget(actor, id);
    const granted = await this.promote(target);

    try {
      await this.revokeAllSessionsOrFail(target.id);
    } catch {
      // Same rule as block: the role change is not rolled back, nothing is
      // recorded, and the next attempt finishes the revocation.
      this.logger.warn(
        { requestId, action: ADMIN_AUDIT_ACTIONS.ADMIN_GRANT },
        'admin session revoke failed',
      );

      throw new InternalServerErrorException();
    }

    if (!granted) return;

    const notified = await this.notifyOwner(actor.id, target.id, requestId);

    await this.recordSuccess(ADMIN_AUDIT_ACTIONS.ADMIN_GRANT, actor.id, target.id, requestId, {
      from: target.role,
      to: Role.ADMIN,
      notified,
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
   */
  private async promote(target: AdminTarget): Promise<boolean> {
    if (target.role === Role.ADMIN) return false;

    if (await this.sessions.setRoleIf(target.id, target.role, Role.ADMIN)) return true;

    // Lost a race: only a concurrent grant of the same privilege is acceptable.
    const current = await this.loadTarget(target.id);

    if (current.found && current.target.role === Role.ADMIN) return false;

    throw new ForbiddenException();
  }

  /**
   * Best effort by contract: the grant already happened, so a failed delivery is
   * logged without ids and reported in the audit metadata, never undone.
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
   */
  async recordSuccess(
    action: AdminAuditAction,
    actorId: string,
    targetId: string,
    requestId: string,
    extraMeta: Record<string, unknown> = {},
  ): Promise<void> {
    try {
      await this.audit.record({
        action,
        actorId,
        targetType: AUDIT_TARGET_TYPE,
        targetId,
        requestId,
        // Callers pass counts and roles at most: never a phone number or a name.
        metadata: extraMeta,
      });
    } catch {
      this.logger.warn({ requestId, action }, 'admin audit failed');

      throw new ServiceUnavailableException();
    }
  }
}
