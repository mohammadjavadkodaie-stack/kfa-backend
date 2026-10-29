import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../../audit/audit.service';
import { Roles } from '../decorators/roles.decorator';
import type { AuthenticatedRequest, RequestPrincipal } from '../guards/auth.guard';
import { parseBody } from '../otp/otp.schema';
import { Role } from '../roles';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';
import { AllowWithoutSecondFactor } from './staff-gate.guard';
import { STEPUP_WINDOW_MS } from './step-up.guard';
import { totpCodeSchema, totpEnrollSchema } from './totp.schema';
import { TotpService, type TotpStatus } from './totp.service';

/** Once only: the authenticator app or password manager holds it afterwards. */
export interface TotpEnrollResponse {
  readonly secretBase32: string;
  readonly otpauthUri: string;
}

export interface TotpConfirmResponse {
  readonly recoveryCodes: string[];
}

export interface TotpStepUpResponse {
  readonly ok: true;
  readonly validForSeconds: number;
}

/** The global guard already rejected anything without a trusted principal. */
function requirePrincipal(request: AuthenticatedRequest): RequestPrincipal {
  const auth = request.auth;

  if (auth === undefined) throw new UnauthorizedException();

  return auth;
}

/**
 * The second factor of a staff account.
 *
 * Every route requires the access token plus ADMIN or OWNER, and every one of
 * them refuses a wrong input with the same generic answer: a caller learns
 * whether a code was close, replayed or locked out only if we tell them, so we
 * do not. The service below stays role-agnostic.
 */
@Controller('auth/totp')
@Roles(Role.ADMIN, Role.OWNER)
@AllowWithoutSecondFactor()
export class TotpController {
  constructor(
    private readonly totp: TotpService,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
  ) {}

  @Get('status')
  @HttpCode(HttpStatus.OK)
  async status(@Req() request: AuthenticatedRequest): Promise<TotpStatus> {
    return this.totp.getStatus(requirePrincipal(request).userId);
  }

  /**
   * The label is the username: a phone number or an e-mail would end up
   * displayed inside the authenticator app of whoever scans the QR code.
   */
  @Post('enroll')
  @HttpCode(HttpStatus.OK)
  async enroll(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<TotpEnrollResponse> {
    const principal = requirePrincipal(request);

    // An empty body is the contract; anything in it is a malformed request.
    if (parseBody(totpEnrollSchema, body ?? {}) === null) throw new BadRequestException();

    const username = await this.sessions.findUsernameByUserId(principal.userId);

    if (username === null) throw new UnauthorizedException();

    const start = await this.totp.startEnrollment(principal.userId, username);

    return { secretBase32: start.secretBase32, otpauthUri: start.otpauthUri };
  }

  /** Malformed body, wrong code, replay, lockout and nothing-pending look alike. */
  @Post('confirm')
  @HttpCode(HttpStatus.OK)
  async confirm(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<TotpConfirmResponse> {
    const principal = requirePrincipal(request);
    const input = parseBody(totpCodeSchema, body);

    if (input === null) throw new UnauthorizedException();

    const result = await this.totp.confirmEnrollment(principal.userId, input.code, Date.now());

    if (result.outcome !== 'confirmed') throw new UnauthorizedException();

    // This session just proved possession, so enrolling must not lock it out.
    // The credential is stored either way: a failed stamp still releases the codes.
    await this.sessions.markStepUp(principal.sessionId, principal.userId);

    return { recoveryCodes: result.recoveryCodes };
  }

  /**
   * Re-authentication for a sensitive action: the code must be fresh, and the
   * window opens for this session only. A recovery code is accepted once.
   */
  @Post('stepup')
  @HttpCode(HttpStatus.OK)
  async stepup(
    @Body() body: unknown,
    @Req() request: AuthenticatedRequest,
  ): Promise<TotpStepUpResponse> {
    const principal = requirePrincipal(request);
    const input = parseBody(totpCodeSchema, body);

    if (input === null) throw new UnauthorizedException();

    const verification = await this.totp.verifyCode(principal.userId, input.code, Date.now());

    if (!verification.ok) throw new UnauthorizedException();

    // A code that verified but could not be stamped is still not a step-up.
    if (!(await this.sessions.markStepUp(principal.sessionId, principal.userId))) {
      throw new UnauthorizedException();
    }

    await this.writeAudit(principal.userId, verification.method);

    return { ok: true, validForSeconds: STEPUP_WINDOW_MS / 1_000 };
  }

  /** Details carry the method only: never the code, a secret or a recovery code. */
  private async writeAudit(userId: string, method: 'totp' | 'recovery'): Promise<void> {
    try {
      await this.audit.record({
        action: 'auth.stepup',
        actorId: userId,
        targetType: 'user',
        targetId: userId,
        metadata: { method },
      });
    } catch {
      // The step-up already happened; a broken trail must not undo it.
      this.logger.warn({ userId, action: 'auth.stepup' }, 'step-up audit failed');
    }
  }
}
