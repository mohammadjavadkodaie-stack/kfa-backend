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
import { ProfilePhotosController } from './photos/profile-photos.controller';
import { ProfilePhotosService } from './photos/profile-photos.service';
import { PrismaProfilePhotoRepository } from './photos/prisma-profile-photo.repository';

@Module({
  // AuthModule supplies the one ownership check; AuditModule the append-only trail.
  // DocumentsModule supplies the ingest, crypto and storage seams the photo
  // upload reuses, and RateLimitModule the shared counters behind its limits.
  imports: [AuthModule, AuditModule, BillingModule, DocumentsModule, RateLimitModule],
  controllers: [AthleteController, ProfilePhotosController],
  providers: [
    AthleteService,
    { provide: ATHLETE_PROFILE_REPOSITORY, useClass: PrismaAthleteProfileRepository },
    // Photos: one service, one repository, no second pipeline.
    ProfilePhotosService,
    { provide: PROFILE_PHOTO_REPOSITORY, useClass: PrismaProfilePhotoRepository },
    // Production time; the specs override this token with a fixed clock.
    { provide: CLOCK, useValue: SYSTEM_CLOCK },
  ],
  // Exported so the review module reads and writes the same profile rows and the
  // same clock instead of declaring a second binding of either.
  exports: [AthleteService, ATHLETE_PROFILE_REPOSITORY, CLOCK],
})
export class AthleteModule implements NestModule {
  /** A photo is private to its owner, so no answer of these routes is cacheable. */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(noStoreMiddleware).forRoutes(ProfilePhotosController);
  }
}
