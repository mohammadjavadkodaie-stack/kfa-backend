import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';

/**
 * Prisma client bound to the runtime role (`kfa_app`).
 *
 * - The URL comes from the validated environment, not from the schema, so the
 *   process can never accidentally use the migrator credentials.
 * - Query/parameter logging is disabled (`log: []`) and errors are minimal:
 *   Prisma error payloads can contain row data and must not reach the logs.
 * - `$connect` runs at boot (fail fast) and `$disconnect` on graceful shutdown.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor(@Inject(ENV) env: Env) {
    super({
      datasourceUrl: env.DATABASE_URL,
      log: [],
      errorFormat: 'minimal',
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
