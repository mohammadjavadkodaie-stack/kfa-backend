import { Module } from '@nestjs/common';
import { AthleteModule } from '../athlete/athlete.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { BillingModule } from '../billing/billing.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { PrismaStaffReviewRepository } from './prisma-staff-review.repository';
import { REVIEW_RESULT_NOTIFIER, EmailReviewResultNotifier } from './review-result-notifier';
import { StaffReviewController } from './staff-review.controller';
import { STAFF_REVIEW_REPOSITORY } from './staff-review.repository';
import { StaffReviewService } from './staff-review.service';

@Module({
  // AuthModule supplies the shared guards, the policy and the email transport;
  // AthleteModule owns the profile repository and the clock this module reads;
  // AuditModule is the append-only trail every decision writes to;
  // NotificationsModule is the in-site inbox a decision also writes to.
  imports: [AuthModule, AthleteModule, AuditModule, BillingModule, NotificationsModule],
  controllers: [StaffReviewController],
  providers: [
    StaffReviewService,
    { provide: STAFF_REVIEW_REPOSITORY, useClass: PrismaStaffReviewRepository },
    // Swapped for a recording notifier in the service tests.
    { provide: REVIEW_RESULT_NOTIFIER, useClass: EmailReviewResultNotifier },
  ],
})
export class StaffReviewModule {}
