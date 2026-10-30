import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { TotpModule } from '../auth/totp/totp.module';
import { AdminUsersController } from './admin-users.controller';
import { AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier, OWNER_NOTIFIER } from './owner-notifier';

@Module({
  // TotpModule supplies the credential store the owner reset deletes from.
  imports: [AuthModule, AuditModule, TotpModule],
  controllers: [AdminUsersController],
  providers: [AdminUsersService, { provide: OWNER_NOTIFIER, useClass: LogOwnerNotifier }],
  exports: [AdminUsersService],
})
export class AdminUsersModule {}
