import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { COMPANY_REPOSITORY } from './company.repository';
import { CompanyService } from './company.service';
import { PrismaCompanyRepository } from './prisma-company.repository';
import { PrismaPublicCompanyRepository } from './prisma-public-company.repository';
import { PublicCompanyController } from './public-company.controller';
import { PUBLIC_COMPANY_REPOSITORY } from './public-company.repository';
import { PublicCompanyService } from './public-company.service';
import { StaffCompanyController } from './staff-company.controller';

@Module({
  // AuthModule supplies the shared guards; AuditModule the append-only trail each
  // company change joins in its own transaction; RateLimitModule the per-address
  // budgets of the public reads.
  imports: [AuthModule, AuditModule, RateLimitModule],
  controllers: [StaffCompanyController, PublicCompanyController],
  providers: [
    CompanyService,
    { provide: COMPANY_REPOSITORY, useClass: PrismaCompanyRepository },
    PublicCompanyService,
    { provide: PUBLIC_COMPANY_REPOSITORY, useClass: PrismaPublicCompanyRepository },
  ],
})
export class CompanyModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // A staff card carries legal identity data: no proxy or browser may cache an
    // answer. The public card is the opposite - its own controller sets a short
    // public lifetime - so it is scoped out of this middleware.
    consumer.apply(noStoreMiddleware).forRoutes(StaffCompanyController);
  }
}
