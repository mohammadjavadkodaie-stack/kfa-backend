import { PasswordService } from './password/password.service';

import { Module, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { AuditModule } from '../audit/audit.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { PrismaModule } from '../database/prisma.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { SecurityAlertsModule } from '../security-alerts/security-alerts.module';
import { REDIS_CLIENT } from '../rate-limit/redis-throttler.storage';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { EmailAuthService } from './email-auth/email-auth.service';
import { EmailAuthController } from './email-auth/email-auth.controller';
import { PasswordResetService } from './email-auth/password-reset.service';
import { MeController } from './me.controller';
import {
  CaptchaProvider,
  CAPTCHA_PROVIDER,
  createCaptchaProvider,
} from './captcha/captcha.provider';
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
import {
  PROOF_NONCE_STORE,
  RedisProofNonceStore,
  type ProofNonceStore,
  type ProofRedisClient,
} from './proof/proof-nonce.store';
import { AccessPolicyService } from './policy/access-policy.service';
import { ResourceOwnershipService } from './policy/resource-ownership.service';
import { PrismaSessionRepository } from './prisma-session.repository';
import { SESSION_REPOSITORY } from './session.repository';
import { StaffGateGuard } from './totp/staff-gate.guard';
import { StepUpGuard } from './totp/step-up.guard';
import { TotpController } from './totp/totp.controller';
import { TotpModule } from './totp/totp.module';

@Module({
  imports: [RateLimitModule, AuditModule, PrismaModule, TotpModule, SecurityAlertsModule],
  controllers: [AuthController, EmailAuthController, MeController, TotpController],
  providers: [
    {
      provide: EMAIL_PROVIDER,
      inject: [ENV],
      useFactory: (
        env: Pick<Env, 'NODE_ENV' | 'EMAIL_PROVIDER' | 'RESEND_API_KEY' | 'EMAIL_FROM'> &
          Partial<Pick<Env, 'EMAIL_CODE_TTL_SECONDS'>>,
      ): EmailProvider => createEmailProvider(env),
    },
    {
      provide: CAPTCHA_PROVIDER,
      inject: [ENV, PinoLogger],
      useFactory: (
        env: Pick<
          Env,
          'NODE_ENV' | 'CAPTCHA_PROVIDER' | 'TURNSTILE_SECRET_KEY' | 'TURNSTILE_EXPECTED_HOSTNAME'
        >,
        logger: PinoLogger,
      ): CaptchaProvider => createCaptchaProvider(env, logger),
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
    EmailProofService,
    EmailCodeService,
    AuthService,
    EmailAuthService,
    PasswordResetService,
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
    CAPTCHA_PROVIDER,
    // The one email transport; the review module sends decision mail through it
    // instead of building an adapter of its own.
    EMAIL_PROVIDER,
    SESSION_REPOSITORY,
    // The one one-time store every short-lived proof spends its nonce in; the
    // profile-photo view links reuse it instead of opening a second store.
    PROOF_NONCE_STORE,
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
