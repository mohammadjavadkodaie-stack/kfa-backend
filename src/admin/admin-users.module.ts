import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { TotpModule } from '../auth/totp/totp.module';
import { DangerousActionsModule } from '../dangerous-actions/dangerous-actions.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { AdminUsersController } from './admin-users.controller';
import { AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier, OWNER_NOTIFIER } from './owner-notifier';

@Module({
  // TotpModule supplies the credential store the owner reset deletes from.
  imports: [AuthModule, AuditModule, TotpModule, DangerousActionsModule],
  controllers: [AdminUsersController],
  providers: [AdminUsersService, { provide: OWNER_NOTIFIER, useClass: LogOwnerNotifier }],
  exports: [AdminUsersService],
})
export class AdminUsersModule implements NestModule {
  /**
   * A page of accounts is every address at once: no proxy or browser may cache
   * an answer, refusals included.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(noStoreMiddleware).forRoutes(AdminUsersController);
  }
}
