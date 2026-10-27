import { Global, Module } from '@nestjs/common';
import { loadEnv, type Env } from './env';

/** DI token for the validated, immutable environment. */
export const ENV = Symbol('ENV');

@Global()
@Module({
  providers: [{ provide: ENV, useFactory: (): Env => loadEnv() }],
  exports: [ENV],
})
export class AppConfigModule {}
