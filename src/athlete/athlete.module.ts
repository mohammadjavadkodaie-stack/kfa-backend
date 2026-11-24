import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { BillingModule } from '../billing/billing.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { DocumentsModule } from '../documents/documents.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { AthleteController } from './athlete.controller';
import { AthleteService } from './athlete.service';
import { CLOCK, SYSTEM_CLOCK } from './profile/athlete-age';
import { ATHLETE_PROFILE_REPOSITORY } from './profile/athlete-profile.repository';
import { PrismaAthleteProfileRepository } from './profile/prisma-athlete-profile.repository';
import { PROFILE_PHOTO_REPOSITORY } from './photos/profile-photo.repository';
import { PROFILE_PHOTO_REPORT_REPOSITORY } from './photos/profile-photo-report.repository';
import { ProfilePhotoReportController } from './photos/profile-photo-report.controller';
import { ProfilePhotoReportService } from './photos/profile-photo-report.service';
import { PrismaProfilePhotoReportRepository } from './photos/prisma-profile-photo-report.repository';
import { PROFILE_PHOTO_VIEW_REPOSITORY } from './photos/profile-photo-view.repository';
import { PrismaProfilePhotoViewRepository } from './photos/prisma-profile-photo-view.repository';
import { ProfilePhotoViewFileController } from './photos/profile-photo-view-file.controller';
import { ProfilePhotoViewService } from './photos/profile-photo-view.service';
import { ProfilePhotosController } from './photos/profile-photos.controller';
import { ProfilePhotosService } from './photos/profile-photos.service';
import { PrismaProfilePhotoRepository } from './photos/prisma-profile-photo.repository';
import { PublicProfilePhotosController } from './photos/public-profile-photos.controller';
import { AthleteFollowController } from './social/athlete-follow.controller';
import { ATHLETE_FOLLOW_REPOSITORY } from './social/athlete-follow.repository';
import { AthleteFollowService } from './social/athlete-follow.service';
import { PhotoLikeController } from './social/photo-like.controller';
import { PHOTO_LIKE_REPOSITORY } from './social/photo-like.repository';
import { PhotoLikeService } from './social/photo-like.service';
import { PrismaAthleteFollowRepository } from './social/prisma-athlete-follow.repository';
import { PrismaPhotoLikeRepository } from './social/prisma-photo-like.repository';

@Module({
  // AuthModule supplies the one ownership check; AuditModule the append-only trail.
  // DocumentsModule supplies the ingest, crypto and storage seams the photo
  // upload reuses, and RateLimitModule the shared counters behind its limits.
  imports: [AuthModule, AuditModule, BillingModule, DocumentsModule, RateLimitModule],
  controllers: [
    AthleteController,
    ProfilePhotosController,
    // Reporting another account's photo: any signed-in caller, APPROVED only.
    ProfilePhotoReportController,
    // The unauthenticated surface: one approved photo's bytes, one approved
    // listing, and the single-use preview link both marked `@Public()`.
    PublicProfilePhotosController,
    ProfilePhotoViewFileController,
    // Following and liking: any signed-in caller, counted per user and address.
    AthleteFollowController,
    PhotoLikeController,
  ],
  providers: [
    AthleteService,
    { provide: ATHLETE_PROFILE_REPOSITORY, useClass: PrismaAthleteProfileRepository },
    // Photos: one service, one repository, no second pipeline.
    ProfilePhotosService,
    { provide: PROFILE_PHOTO_REPOSITORY, useClass: PrismaProfilePhotoRepository },
    // Reports: an append-only side table, its own service so the upload pipeline
    // never learns what a report is.
    ProfilePhotoReportService,
    { provide: PROFILE_PHOTO_REPORT_REPOSITORY, useClass: PrismaProfilePhotoReportRepository },
    // Serving: a read-only view service over the same rows, the same crypto and
    // the same storage - never a second copy of either.
    ProfilePhotoViewService,
    { provide: PROFILE_PHOTO_VIEW_REPOSITORY, useClass: PrismaProfilePhotoViewRepository },
    // Production time; the specs override this token with a fixed clock.
    { provide: CLOCK, useValue: SYSTEM_CLOCK },
    // Stage 7c: one repository each, so a follow and a like never reach into
    // another feature's storage seam.
    AthleteFollowService,
    { provide: ATHLETE_FOLLOW_REPOSITORY, useClass: PrismaAthleteFollowRepository },
    PhotoLikeService,
    { provide: PHOTO_LIKE_REPOSITORY, useClass: PrismaPhotoLikeRepository },
  ],
  // Exported so the review module reads and writes the same profile rows and the
  // same clock instead of declaring a second binding of either, and issues its
  // preview links through the very service the owner route uses.
  exports: [AthleteService, ATHLETE_PROFILE_REPOSITORY, CLOCK, ProfilePhotoViewService],
})
export class AthleteModule implements NestModule {
  /**
   * A photo is private to its owner and the serving routes must not be cached,
   * so no answer of these routes is cacheable. REJECTED rows are never served;
   * the public routes additionally refuse anything not APPROVED.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(noStoreMiddleware)
      .forRoutes(
        ProfilePhotosController,
        ProfilePhotoReportController,
        PublicProfilePhotosController,
        ProfilePhotoViewFileController,
        AthleteFollowController,
        PhotoLikeController,
      );
  }
}
