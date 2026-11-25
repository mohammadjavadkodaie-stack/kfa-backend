import { Module } from '@nestjs/common';
import { PrismaModule } from '../database/prisma.module';
import { DangerousActionsController } from './dangerous-actions.controller';
import { DangerousActionsService } from './dangerous-actions.service';
import { PendingApprovalRepository } from './pending-approval.repository';

@Module({
  imports: [PrismaModule],
  controllers: [DangerousActionsController],
  providers: [PendingApprovalRepository, DangerousActionsService],
  exports: [DangerousActionsService],
})
export class DangerousActionsModule {}
