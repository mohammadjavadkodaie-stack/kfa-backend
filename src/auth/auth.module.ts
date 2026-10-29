import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { ENV } from '../config/config.module';
import { PrismaModule } from '../database/prisma.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { REDIS_CLIENT } from '../rate-limit/redis-throttler.storage';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { CaptchaProvider, CAPTCHA_PROVIDER, FakeCaptchaProvider } from './captcha/captcha.provider';
import { AuthGuard } from './guards/auth.guard';
import { OriginCheckGuard } from './guards/origin.guard';
import { OtpController } from './otp/otp.controller';
import { FakeOtpProvider, OTP_PROVIDER, OtpProvider } from './otp/otp.provider';
import { OtpService } from './otp/otp.service';
import {
  PROOF_NONCE_STORE,
  ProofTokenService,
  RedisProofNonceStore,
  type ProofNonceStore,
  type ProofRedisClient,
} from './otp/proof-token';
import { PrismaSessionRepository } from './prisma-session.repository';
import { SESSION_REPOSITORY } from './session.repository';

@Module({
  imports: [RateLimitModule, AuditModule, PrismaModule],
  controllers: [OtpController, AuthController],
  providers: [
    {
      provide: OTP_PROVIDER,
      inject: [ENV],
      useFactory: (env: { OTP_PROVIDER: string }): OtpProvider => {
        if (env.OTP_PROVIDER !== 'fake') throw new Error('Unsupported OTP_PROVIDER');
        return new FakeOtpProvider();
      },
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
      // Swapped for the in-memory fake in the service tests; the singleton keeps
      // a single Prisma-backed instance for the whole process.
      provide: SESSION_REPOSITORY,
      useClass: PrismaSessionRepository,
    },
    ProofTokenService,
    OtpService,
    AuthService,
    AuthGuard,
    OriginCheckGuard,
  ],
  exports: [
    OTP_PROVIDER,
    CAPTCHA_PROVIDER,
    ProofTokenService,
    SESSION_REPOSITORY,
    // Exported so the global guard and later modules share one definition.
    AuthGuard,
    AuthService,
  ],
})
export class AuthModule {}
