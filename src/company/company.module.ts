import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { COMPANY_REPOSITORY } from './company.repository';
import { CompanyService } from './company.service';
import { PrismaCompanyRepository } from './prisma-company.repository';
import { StaffCompanyController } from './staff-company.controller';

@Module({
  // AuthModule supplies the shared guards; AuditModule the append-only trail each
  // company change joins in its own transaction.
  imports: [AuthModule, AuditModule],
  controllers: [StaffCompanyController],
  providers: [CompanyService, { provide: COMPANY_REPOSITORY, useClass: PrismaCompanyRepository }],
})
export class CompanyModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // A card carries legal identity data: no proxy or browser may cache an
    // answer, and step 9b's public read is a different controller.
    consumer.apply(noStoreMiddleware).forRoutes(StaffCompanyController);
  }
}
