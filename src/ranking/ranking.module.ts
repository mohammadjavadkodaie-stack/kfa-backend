import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { PrismaPublicRankingRepository } from './prisma-public-ranking.repository';
import { PrismaRankingRepository } from './prisma-ranking.repository';
import { PublicRankingController } from './public-ranking.controller';
import { PUBLIC_RANKING_REPOSITORY } from './public-ranking.repository';
import { PublicRankingService } from './public-ranking.service';
import { RANKING_REPOSITORY } from './ranking.repository';
import { RankingService } from './ranking.service';
import { StaffRankingController } from './staff-ranking.controller';

@Module({
  // AuthModule supplies the shared guards; AuditModule the append-only trail the
  // result change and every rank change join; RateLimitModule the per-user budget
  // behind a staff write and the per-address budgets of the public reads.
  imports: [AuthModule, AuditModule, RateLimitModule],
  controllers: [StaffRankingController, PublicRankingController],
  providers: [
    RankingService,
    { provide: RANKING_REPOSITORY, useClass: PrismaRankingRepository },
    PublicRankingService,
    { provide: PUBLIC_RANKING_REPOSITORY, useClass: PrismaPublicRankingRepository },
  ],
})
export class RankingModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Result rows are staff data: no proxy or browser may cache an answer. The
    // public leaderboard is the opposite and is scoped out of this middleware.
    consumer.apply(noStoreMiddleware).forRoutes(StaffRankingController);
  }
}
