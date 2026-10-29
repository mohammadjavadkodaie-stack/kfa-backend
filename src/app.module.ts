import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { LoggerModule } from 'nestjs-pino';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { AuthGuard } from './auth/guards/auth.guard';
import { RolesGuard } from './auth/guards/roles.guard';
import { StaffGateGuard } from './auth/totp/staff-gate.guard';
import { StepUpGuard } from './auth/totp/step-up.guard';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { AppConfigModule, ENV } from './config/config.module';
import type { Env } from './config/env';
import { PrismaModule } from './database/prisma.module';
import { HealthModule } from './health/health.module';
import { buildPinoParams } from './logging/pino.config';
import { RateLimitModule } from './rate-limit/rate-limit.module';

@Module({
  imports: [
    AppConfigModule,
    LoggerModule.forRootAsync<Request, Response>({
      inject: [ENV],
      useFactory: (env: Env) => buildPinoParams(env),
    }),
    RateLimitModule,
    PrismaModule,
    AuditModule,
    AuthModule,
    HealthModule,
  ],
  providers: [
    // Order matters: throttle before authenticating so unauthenticated floods
    // are still rate limited; StaffGateGuard sits right after the token check so
    // no role or step-up decision ever sees a staff session that never proved a
    // second factor; RolesGuard then reads the principal AuthGuard already
    // loaded, and StepUpGuard runs last, so it only ever sees a staff principal.
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: StaffGateGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_GUARD, useClass: StepUpGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule {}
