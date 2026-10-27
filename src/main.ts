import 'reflect-metadata';
import { Logger as NestLogger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';
import { ENV } from './config/config.module';
import type { Env } from './config/env';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    // Body parsing is registered explicitly in `configureApp` so the size limit
    // comes from the validated environment instead of the library default.
    bodyParser: false,
    bufferLogs: true,
  });

  app.useLogger(app.get(Logger));

  const env = app.get<Env>(ENV);
  configureApp(app, env);
  app.enableShutdownHooks();

  await app.listen(env.PORT);
}

void bootstrap().catch((error: unknown) => {
  // Logger may not exist yet (boot failed); never print env values or stacks.
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  new NestLogger('Bootstrap').error(message);
  process.exit(1);
});
