import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { ENV } from '../config/config.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { REDIS_CLIENT } from '../rate-limit/redis-throttler.storage';
import { CaptchaProvider, CAPTCHA_PROVIDER, FakeCaptchaProvider } from './captcha/captcha.provider';
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

@Module({
  imports: [RateLimitModule, AuditModule],
  controllers: [OtpController],
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
    ProofTokenService,
    OtpService,
  ],
  exports: [OTP_PROVIDER, CAPTCHA_PROVIDER, ProofTokenService],
})
export class AuthModule {}
