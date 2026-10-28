import { Module } from '@nestjs/common';
import { ENV } from '../config/config.module';
import { CaptchaProvider, CAPTCHA_PROVIDER, FakeCaptchaProvider } from './captcha/captcha.provider';
import { FakeOtpProvider, OTP_PROVIDER, OtpProvider } from './otp/otp.provider';

@Module({
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
  ],
  exports: [OTP_PROVIDER, CAPTCHA_PROVIDER],
})
export class AuthModule {}
