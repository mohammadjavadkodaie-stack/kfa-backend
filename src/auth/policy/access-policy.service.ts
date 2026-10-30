import { ForbiddenException, Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { parseRole, Role } from '../roles';
import {
  decide as decidePolicy,
  parseAccessAction,
  type AccessRequest,
  type DenialReason,
  type PolicyDecision,
  type PolicySubject,
} from './access-policy';

/** Request facts an audit row may carry; nothing else leaves this service. */
export interface AccessPolicyContext {
  readonly requestId: string;
  /** Raw client IP. The audit service hashes it before it is stored. */
  readonly ip: string | null;
}

const DENIED_ACTION = 'authz.denied';
const AUDIT_TARGET_TYPE = 'user';
/** Written instead of a value that is not part of the closed set. */
const UNKNOWN = 'unknown';

/**
 * Authorization for administrative actions. The rule set itself is the pure
 * `decide()` function; this class only adds what a pure function cannot do:
 * answer the client and leave a trace.
 *
 * Every refusal is the same generic 403 the roles guard returns, so the client
 * learns neither the rule that stopped it nor the reason code.
 */
@Injectable()
export class AccessPolicyService {
  constructor(
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  /**
   * The pure rule set, for a caller that answers with its own generic refusal
   * instead of an HTTP exception. It writes nothing and logs nothing.
   */
  decide(actor: PolicySubject, request: AccessRequest, target: PolicySubject): PolicyDecision {
    return decidePolicy(actor, request, target);
  }

  /**
   * Resolves when the action is allowed and throws the generic
   * `ForbiddenException` otherwise. A refused staff action is audited once,
   * before the throw: losing the trail never turns a refusal into an allow.
   */
  async authorize(
    actor: PolicySubject,
    request: AccessRequest,
    target: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<void> {
    const decision = decidePolicy(actor, request, target);

    if (decision.allowed) return;

    this.logger.warn(
      { requestId: context.requestId, reason: decision.reason, action: DENIED_ACTION },
      'access denied',
    );

    await this.auditDenial(actor, request, target, decision.reason, context);

    throw new ForbiddenException();
  }

  /**
   * One row for a refused staff action. Only ADMIN and OWNER actors are
   * recorded: a USER or ATHLETE never reaches a staff endpoint (the roles guard
   * stops it first) and is refused here without an entry.
   *
   * The metadata is limited to four values that cannot carry request text: a
   * role, an action from the closed set, a target id and a role. A value that is
   * not recognised is stored as "unknown" rather than echoed.
   */
  private async auditDenial(
    actor: PolicySubject,
    request: AccessRequest,
    target: PolicySubject,
    reason: DenialReason,
    context: AccessPolicyContext,
  ): Promise<void> {
    const actorRole = parseRole(String(actor.role));

    if (actorRole !== Role.ADMIN && actorRole !== Role.OWNER) return;

    const targetRole = parseRole(String(target.role));

    try {
      await this.audit.record({
        action: DENIED_ACTION,
        actorId: actor.id,
        actorRole,
        targetType: AUDIT_TARGET_TYPE,
        targetId: target.id,
        requestId: context.requestId,
        ip: context.ip,
        metadata: {
          actorRole,
          action: parseAccessAction(String(request.action)) ?? UNKNOWN,
          targetId: target.id,
          targetRole: targetRole ?? UNKNOWN,
        },
      });
    } catch {
      // Fail closed: the refusal stands whether or not the row was written.
      // Only codes are logged - no id, no phone number, no message from the
      // exception (an invalid field name could quote client data).
      this.logger.warn(
        { requestId: context.requestId, reason, action: DENIED_ACTION },
        'authz audit failed',
      );
    }
  }
}
