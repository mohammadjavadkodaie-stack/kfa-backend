import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { AdminUsersService } from './admin-users.service';
import { LogOwnerNotifier, OWNER_NOTIFIER } from './owner-notifier';

@Module({
  imports: [AuthModule, AuditModule],
  providers: [AdminUsersService, { provide: OWNER_NOTIFIER, useClass: LogOwnerNotifier }],
  exports: [AdminUsersService],
})
export class AdminUsersModule {}
