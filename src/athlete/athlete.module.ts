import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { AthleteController } from './athlete.controller';
import { AthleteService } from './athlete.service';
import { CLOCK, SYSTEM_CLOCK } from './profile/athlete-age';
import { ATHLETE_PROFILE_REPOSITORY } from './profile/athlete-profile.repository';
import { PrismaAthleteProfileRepository } from './profile/prisma-athlete-profile.repository';

@Module({
  // AuthModule supplies the one ownership check; AuditModule the append-only trail.
  imports: [AuthModule, AuditModule],
  controllers: [AthleteController],
  providers: [
    AthleteService,
    { provide: ATHLETE_PROFILE_REPOSITORY, useClass: PrismaAthleteProfileRepository },
    // Production time; the specs override this token with a fixed clock.
    { provide: CLOCK, useValue: SYSTEM_CLOCK },
  ],
  exports: [AthleteService],
})
export class AthleteModule {}
