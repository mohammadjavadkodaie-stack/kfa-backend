import {
  BadRequestException,
  ConflictException,
  HttpException,
  Inject,
  Injectable,
  Optional,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  AuthService,
  REGISTER_IP_LIMIT,
  type AuthRequestContext,
  type AuthResult,
} from '../auth.service';
import { usernameSchema } from '../auth.schema';
import { EmailProofService } from '../email/email-proof';
import { EmailCodeService } from '../email/email-code.service';
import { hashDeviceKey } from '../device-key';
import { maskEmail, normalizeEmail } from '../email/email';
import { PasswordBusyError, PasswordService } from '../password/password.service';
import { validatePassword } from '../password/password.policy';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';

const SIGNUP_IP_LIMIT = { ...REGISTER_IP_LIMIT } as const;
const SIGNIN_IP_LIMIT = { limit: 20, windowSeconds: 900 } as const;
const SIGNIN_DEVICE_LIMIT = { limit: 10, windowSeconds: 900 } as const;
const SIGNIN_FAIL_EMAIL_IP_LIMIT = { limit: 5, windowSeconds: 900 } as const;
const SIGNIN_FAIL_EMAIL_LIMIT = { limit: 30, windowSeconds: 3600 } as const;

function invalidCredentials(): UnauthorizedException {
  return new UnauthorizedException({ error: 'invalid_credentials' });
}

@Injectable()
export class EmailAuthService {
  constructor(
    private readonly auth: AuthService,
    private readonly proof: EmailProofService,
    private readonly password: PasswordService,
    private readonly rateLimit: RateLimitService,
    @Inject(SESSION_REPOSITORY) private readonly sessions: SessionRepository,
    @Optional() private readonly emailCode?: EmailCodeService,
  ) {}

  async signIn(input: {
    readonly email: string;
    readonly password: string;
    readonly deviceKey: string | null;
    readonly deviceName?: string;
    readonly proof: unknown;
    readonly ip: string;
    readonly userAgent?: string;
  }): Promise<AuthResult> {
    const throttle = async (
      scope: string,
      identifier: string,
      limit: number,
      windowSeconds: number,
    ) => {
      const decision = await this.rateLimit.consume({ scope, identifier, limit, windowSeconds });
      if (!decision.allowed)
        throw new HttpException({ error: 'rate_limited' }, 429, { cause: undefined });
    };
    await throttle('signin-ip', input.ip, SIGNIN_IP_LIMIT.limit, SIGNIN_IP_LIMIT.windowSeconds);
    if (input.deviceKey !== null)
      await throttle(
        'signin-device',
        input.deviceKey,
        SIGNIN_DEVICE_LIMIT.limit,
        SIGNIN_DEVICE_LIMIT.windowSeconds,
      );

    const email = normalizeEmail(input.email);
    const failureIp = email === null ? null : `${email}:${input.ip}`;
    if (failureIp !== null) {
      const check = await this.rateLimit.peek({
        scope: 'signin-fail-email-ip',
        identifier: failureIp,
        limit: SIGNIN_FAIL_EMAIL_IP_LIMIT.limit,
      });
      if (!check.allowed) throw new HttpException({ error: 'rate_limited' }, 429);
      const accountCheck = await this.rateLimit.peek({
        scope: 'signin-fail-email',
        identifier: email as string,
        limit: SIGNIN_FAIL_EMAIL_LIMIT.limit,
      });
      if (!accountCheck.allowed) throw new HttpException({ error: 'rate_limited' }, 429);
    }

    const account = email === null ? null : await this.sessions.findUserByEmail(email);
    let valid = false;
    try {
      if (account === null || account.passwordHash === null || account.emailVerifiedAt === null) {
        await this.password.verifyDummy(input.password);
      } else {
        valid = await this.password.verify(input.password, account.passwordHash);
      }
    } catch (error) {
      if (error instanceof PasswordBusyError) throw new ServiceUnavailableException();
      throw error;
    }
    const failCredential = async (): Promise<never> => {
      if (failureIp !== null) {
        await this.rateLimit.consume({
          scope: 'signin-fail-email-ip',
          identifier: failureIp,
          ...SIGNIN_FAIL_EMAIL_IP_LIMIT,
        });
        await this.rateLimit.consume({
          scope: 'signin-fail-email',
          identifier: email as string,
          ...SIGNIN_FAIL_EMAIL_LIMIT,
        });
      }
      throw invalidCredentials();
    };
    if (!valid || account === null) return failCredential();
    const context: AuthRequestContext = {
      ip: input.ip,
      requestId: '',
      deviceKey: input.deviceKey,
      cookieHeader: undefined,
      userAgent: input.userAgent,
    };
    if (account.status !== 'ACTIVE') {
      await this.auth.auditEmailLoginBlocked(email as string, account.id, context);
      throw invalidCredentials();
    }
    if (this.password.needsRehash(account.passwordHash)) {
      try {
        await this.sessions.updatePasswordHash(
          account.id,
          await this.password.hash(input.password),
        );
      } catch (error) {
        if (error instanceof PasswordBusyError) throw new ServiceUnavailableException();
      }
    }
    const deviceHash =
      input.deviceKey === null ? null : this.auth.hashEmailDeviceKey(account.id, input.deviceKey);
    const known =
      deviceHash !== null && (await this.sessions.isKnownDevice(account.id, deviceHash));
    if (!known) {
      if (input.proof === undefined || input.proof === null) {
        if (this.emailCode === undefined) throw new ServiceUnavailableException();
        await this.emailCode.startForVerifiedUser({
          email: email as string,
          purpose: 'login_device',
          ip: input.ip,
          deviceKey: input.deviceKey,
        });
        throw new HttpException({ error: 'device_verification_required' }, 403);
      }
      const proved = await this.proof.consumeEmailProof({
        proof: input.proof,
        purpose: 'login_device',
      });
      if (proved !== email) throw invalidCredentials();
    }
    return this.auth.issueEmailLoginSession({ email: email as string, account, context });
  }

  async signUp(input: {
    readonly proof: unknown;
    readonly username: unknown;
    readonly password: string;
    readonly deviceKey: string | null;
    readonly deviceName?: string;
    readonly ip: string;
    readonly userAgent?: string;
  }): Promise<AuthResult> {
    const decision = await this.rateLimit.consume({
      scope: 'signup-ip',
      identifier: input.ip,
      ...SIGNUP_IP_LIMIT,
    });
    if (!decision.allowed) {
      return { outcome: 'throttled', retryAfterSeconds: decision.retryAfterSeconds };
    }

    const email = await this.proof.consumeEmailProof({ proof: input.proof, purpose: 'register' });
    if (email === null) throw invalidCredentials();

    const parsedUsername = usernameSchema.safeParse(input.username);
    if (!parsedUsername.success) throw new BadRequestException();
    const username = parsedUsername.data;

    const policy = validatePassword(input.password, { email, username });
    if (!policy.ok) {
      throw new BadRequestException({ error: 'weak_password', reason: policy.reason });
    }

    let passwordHash: string;
    try {
      passwordHash = await this.password.hash(input.password);
    } catch (error) {
      if (error instanceof PasswordBusyError) throw error;
      throw error;
    }

    if (await this.sessions.isUsernameTaken(username)) {
      throw new ConflictException({ error: 'unavailable' });
    }
    if (await this.sessions.findUserByEmail(email)) {
      throw new ConflictException({ error: 'unavailable' });
    }

    const context: AuthRequestContext = {
      ip: input.ip,
      requestId: '',
      deviceKey: input.deviceKey,
      cookieHeader: undefined,
      userAgent: input.userAgent,
    };

    try {
      return await this.auth.issueEmailAccountSession({
        email,
        username,
        passwordHash,
        deviceName: input.deviceName,
        context,
      });
    } catch (error) {
      if (error instanceof ConflictException) {
        throw new ConflictException({ error: 'unavailable' });
      }
      throw error;
    }
  }
}
