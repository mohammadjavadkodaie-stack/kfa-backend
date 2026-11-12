import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
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
import { PasswordBusyError, PasswordService } from '../password/password.service';
import { validatePassword } from '../password/password.policy';
import { RateLimitService } from '../../rate-limit/rate-limit.service';
import { SESSION_REPOSITORY, type SessionRepository } from '../session.repository';

const SIGNUP_IP_LIMIT = { ...REGISTER_IP_LIMIT } as const;

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
  ) {}

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
