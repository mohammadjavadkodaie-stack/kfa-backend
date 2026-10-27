import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { LoggerModule } from 'nestjs-pino';
import { AuditModule } from './audit/audit.module';
import { AuthGuard } from './auth/guards/auth.guard';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { AppConfigModule, ENV } from './config/config.module';
import type { Env } from './config/env';
import { PrismaModule } from './database/prisma.module';
import { HealthModule } from './health/health.module';
import { buildPinoParams } from './logging/pino.config';
import { buildThrottlerModuleOptions } from './rate-limit/throttler.config';

@Module({
  imports: [
    AppConfigModule,
    LoggerModule.forRootAsync<Request, Response>({
      inject: [ENV],
      useFactory: (env: Env) => buildPinoParams(env),
    }),
    ThrottlerModule.forRootAsync({
      inject: [ENV],
      useFactory: (env: Env) => buildThrottlerModuleOptions(env),
    }),
    PrismaModule,
    AuditModule,
    HealthModule,
  ],
  providers: [
    // Order matters: throttle before authenticating so unauthenticated floods
    // are still rate limited.
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule {}
