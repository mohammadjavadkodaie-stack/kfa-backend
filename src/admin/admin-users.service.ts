import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import { AccessAction, type PolicySubject } from '../auth/policy/access-policy';
import { AccessPolicyService } from '../auth/policy/access-policy.service';
import type { Role } from '../auth/roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../auth/session.repository';
import { isUuid } from '../common/middleware/request-id.middleware';

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
 * Shared helpers for the administrative user endpoints. The controller and the
 * routes arrive in a later step; nothing here answers an HTTP request yet.
 */
@Injectable()
export class AdminUsersService {
  constructor(
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    private readonly policy: AccessPolicyService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
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
