import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { LoggerModule } from 'nestjs-pino';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { AuthGuard } from './auth/guards/auth.guard';
import { RolesGuard } from './auth/guards/roles.guard';
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
    // are still rate limited; RolesGuard must run after AuthGuard so it can
    // read the principal from the database lookup AuthGuard already made.
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule {}
