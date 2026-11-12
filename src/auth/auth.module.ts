import { PasswordService } from './password/password.service';

import { Module, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { PrismaModule } from '../database/prisma.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { REDIS_CLIENT } from '../rate-limit/redis-throttler.storage';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { EmailAuthService } from './email-auth/email-auth.service';
import { EmailAuthController } from './email-auth/email-auth.controller';
import { MeController } from './me.controller';
import { CaptchaProvider, CAPTCHA_PROVIDER, FakeCaptchaProvider } from './captcha/captcha.provider';
import { AuthGuard } from './guards/auth.guard';
import { createEmailProvider, EMAIL_PROVIDER, type EmailProvider } from './email/email.provider';
import { EmailCodeService } from './email/email-code.service';
import { EmailProofService } from './email/email-proof';
import {
  EMAIL_CODE_STORE,
  RedisEmailCodeStore,
  type EmailCodeRedisClient,
  type EmailCodeStore,
} from './email/email-code.store';
import { OriginCheckGuard } from './guards/origin.guard';
import { RolesGuard } from './guards/roles.guard';
import { OtpController } from './otp/otp.controller';
import { createOtpProvider, OTP_PROVIDER, OtpProvider } from './otp/otp.provider';
import { OtpService } from './otp/otp.service';
import {
  PROOF_NONCE_STORE,
  ProofTokenService,
  RedisProofNonceStore,
  type ProofNonceStore,
  type ProofRedisClient,
} from './otp/proof-token';
import { PhoneChangeController } from './phone-change/phone-change.controller';
import { PhoneChangeService } from './phone-change/phone-change.service';
import { AccessPolicyService } from './policy/access-policy.service';
import { ResourceOwnershipService } from './policy/resource-ownership.service';
import { PrismaSessionRepository } from './prisma-session.repository';
import { SESSION_REPOSITORY } from './session.repository';
import { StaffGateGuard } from './totp/staff-gate.guard';
import { StepUpGuard } from './totp/step-up.guard';
import { TotpController } from './totp/totp.controller';
import { TotpModule } from './totp/totp.module';

@Module({
  imports: [RateLimitModule, AuditModule, PrismaModule, TotpModule],
  controllers: [
    OtpController,
    AuthController,
    EmailAuthController,
    MeController,
    PhoneChangeController,
    TotpController,
  ],
  providers: [
    {
      provide: OTP_PROVIDER,
      inject: [ENV],
      // A fake provider in production is a boot error, not a warning.
      useFactory: (env: Pick<Env, 'NODE_ENV' | 'OTP_PROVIDER'>): OtpProvider =>
        createOtpProvider(env),
    },
    {
      provide: EMAIL_PROVIDER,
      inject: [ENV],
      useFactory: (env: Pick<Env, 'NODE_ENV' | 'EMAIL_PROVIDER'>): EmailProvider =>
        createEmailProvider(env),
    },
    {
      provide: CAPTCHA_PROVIDER,
      inject: [ENV],
      useFactory: (env: { CAPTCHA_PROVIDER: string }): CaptchaProvider => {
        if (env.CAPTCHA_PROVIDER !== 'fake') throw new Error('Unsupported CAPTCHA_PROVIDER');
        return new FakeCaptchaProvider();
      },
    },
    {
      provide: PROOF_NONCE_STORE,
      inject: [REDIS_CLIENT],
      useFactory: (client: unknown): ProofNonceStore | null =>
        // Without a shared store there is nowhere to keep a nonce, so proofs
        // fail closed instead of degrading to replayable tokens.
        client === null || client === undefined
          ? null
          : new RedisProofNonceStore(client as ProofRedisClient),
    },
    {
      provide: EMAIL_CODE_STORE,
      inject: [REDIS_CLIENT],
      useFactory: (client: unknown): EmailCodeStore | null =>
        client === null || client === undefined
          ? null
          : new RedisEmailCodeStore(client as EmailCodeRedisClient),
    },
    {
      // Swapped for the in-memory fake in the service tests; the singleton keeps
      // a single Prisma-backed instance for the whole process.
      provide: SESSION_REPOSITORY,
      useClass: PrismaSessionRepository,
    },
    ProofTokenService,
    EmailProofService,
    EmailCodeService,
    OtpService,
    AuthService,
    EmailAuthService,
    PhoneChangeService,
    AuthGuard,
    RolesGuard,
    StepUpGuard,
    StaffGateGuard,
    OriginCheckGuard,
    AccessPolicyService,
    ResourceOwnershipService,
    PasswordService,
  ],
  exports: [
    OTP_PROVIDER,
    CAPTCHA_PROVIDER,
    ProofTokenService,
    SESSION_REPOSITORY,
    // Exported so the global guards and later modules share one definition.
    AuthGuard,
    RolesGuard,
    StepUpGuard,
    StaffGateGuard,
    AuthService,
    // The administrative modules must inject this rather than re-implement a
    // rule; it is the only place that decides and audits a staff action.
    AccessPolicyService,
    // The one ownership check; a resource module injects this instead of
    // comparing user ids on its own.
    ResourceOwnershipService,
  ],
})
export class AuthModule implements NestModule {
  /**
   * Second-factor bodies must never be cached, guard refusals included; the
   * self-description is per-account and must not be stored by a shared cache
   * either.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(noStoreMiddleware).forRoutes(TotpController, MeController, EmailAuthController);
  }
}
