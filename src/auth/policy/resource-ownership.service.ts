import { ForbiddenException, Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { parseRole } from '../roles';
import type { PolicySubject } from './access-policy';
import type { AccessPolicyContext } from './access-policy.service';

/** The same row the access policy writes, so one query finds every refusal. */
const DENIED_ACTION = 'authz.denied';
/** Fixed token for the kind of refusal; never a resource id or a request value. */
const OWNERSHIP_ACTION = 'resource.ownership';
const AUDIT_TARGET_TYPE = 'resource';
/** Written instead of a role that is not part of the closed set. */
const UNKNOWN = 'unknown';

/**
 * Ownership check for a resource that belongs to exactly one user.
 *
 * It is deliberately not a staff action: the only rule is `actor.id ===
 * ownerUserId`, and no role widens it. Reading someone else's document is a
 * separate decision for a later step, so ADMIN and OWNER are refused here like
 * anybody else.
 *
 * The refusal is the generic 403 the guards and the access policy return, and a
 * missing resource is refused the same way as a foreign one: the caller learns
 * nothing about whether the row exists.
 *
 * `AccessPolicyService` is not reused: its rule set refuses every USER/ATHLETE
 * actor outright and audits only staff, which would deny the legitimate owner
 * and leave an ordinary user's denial untraced.
 */
@Injectable()
export class ResourceOwnershipService {
  constructor(
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * Resolves when the actor owns the resource, throws the generic
   * `ForbiddenException` otherwise. `ownerUserId` is null when there is no
   * resource, and that refusal is audited like any other.
   */
  async assertOwnsResource(
    actor: PolicySubject,
    ownerUserId: string | null,
    context: AccessPolicyContext,
  ): Promise<void> {
    if (ownerUserId !== null && ownerUserId === actor.id) return;

    this.logger.warn({ requestId: context.requestId, action: DENIED_ACTION }, 'ownership denied');

    await this.auditDenial(actor, context);

    // Thrown last: a written row must never change the answer, and the missing
    // resource left no earlier trace to tell it apart.
    throw new ForbiddenException();
  }

  /**
   * One row per refusal, for every role: an ownership denial is not staff-only.
   *
   * The metadata carries a role and a fixed action token and nothing else - no
   * resource body, no owner id, so the row cannot leak what was asked for.
   */
  private async auditDenial(actor: PolicySubject, context: AccessPolicyContext): Promise<void> {
    const actorRole = parseRole(String(actor.role)) ?? UNKNOWN;

    try {
      await this.audit.record({
        action: DENIED_ACTION,
        actorId: actor.id,
        actorRole,
        targetType: AUDIT_TARGET_TYPE,
        // No targetId on purpose: a missing resource and a foreign one must
        // leave the same row.
        requestId: context.requestId,
        ip: context.ip,
        metadata: { actorRole, action: OWNERSHIP_ACTION, outcome: 'denied' },
      });
    } catch {
      // Fail closed: the refusal stands whether or not the row was written.
      // Only codes are logged - no id and no message from the exception.
      this.logger.warn(
        { requestId: context.requestId, action: DENIED_ACTION },
        'authz audit failed',
      );
    }
  }
}
