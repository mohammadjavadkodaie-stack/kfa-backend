import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { PrismaRankingRepository } from './prisma-ranking.repository';
import { RANKING_REPOSITORY } from './ranking.repository';
import { RankingService } from './ranking.service';
import { StaffRankingController } from './staff-ranking.controller';

@Module({
  // AuthModule supplies the shared guards; AuditModule the append-only trail the
  // result change and every rank change join; RateLimitModule the per-user budget
  // behind a staff write.
  imports: [AuthModule, AuditModule, RateLimitModule],
  controllers: [StaffRankingController],
  providers: [RankingService, { provide: RANKING_REPOSITORY, useClass: PrismaRankingRepository }],
})
export class RankingModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Result rows are staff data: no proxy or browser may cache an answer.
    consumer.apply(noStoreMiddleware).forRoutes(StaffRankingController);
  }
}
