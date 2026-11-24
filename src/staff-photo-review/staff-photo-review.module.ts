import { Module } from '@nestjs/common';
import { AthleteModule } from '../athlete/athlete.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { PrismaStaffPhotoReviewRepository } from './prisma-staff-photo-review.repository';
import { StaffPhotoReviewController } from './staff-photo-review.controller';
import { STAFF_PHOTO_REVIEW_REPOSITORY } from './staff-photo-review.repository';
import { StaffPhotoReviewService } from './staff-photo-review.service';

@Module({
  // AuthModule supplies the shared guards; AthleteModule the production clock the
  // decisions stamp (the specs override that token); AuditModule is the
  // append-only trail every decision writes to.
  imports: [AuthModule, AthleteModule, AuditModule],
  controllers: [StaffPhotoReviewController],
  providers: [
    StaffPhotoReviewService,
    { provide: STAFF_PHOTO_REVIEW_REPOSITORY, useClass: PrismaStaffPhotoReviewRepository },
  ],
})
export class StaffPhotoReviewModule {}
