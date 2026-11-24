import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AthleteModule } from '../athlete/athlete.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { PrismaStaffPhotoReviewRepository } from './prisma-staff-photo-review.repository';
import { StaffPhotoReviewController } from './staff-photo-review.controller';
import { STAFF_PHOTO_REVIEW_REPOSITORY } from './staff-photo-review.repository';
import { StaffPhotoReviewService } from './staff-photo-review.service';

@Module({
  // AuthModule supplies the shared guards; AthleteModule the production clock the
  // decisions stamp (the specs override that token) and the profile-photo view
  // service the preview link comes from; AuditModule is the append-only trail
  // every decision writes to; RateLimitModule backs that link's per-user budget.
  imports: [AuthModule, AthleteModule, AuditModule, RateLimitModule],
  controllers: [StaffPhotoReviewController],
  providers: [
    StaffPhotoReviewService,
    { provide: STAFF_PHOTO_REVIEW_REPOSITORY, useClass: PrismaStaffPhotoReviewRepository },
  ],
})
export class StaffPhotoReviewModule implements NestModule {
  /** Queue rows and reported photos are somebody's images: nothing here is cacheable. */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(noStoreMiddleware).forRoutes(StaffPhotoReviewController);
  }
}
