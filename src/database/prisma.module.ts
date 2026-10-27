import { Global, Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module';
import { PrismaService } from './prisma.service';

/**
 * Single shared Prisma client. Global so feature modules do not have to import
 * it explicitly (and cannot create additional connection pools by accident).
 */
@Global()
@Module({
  imports: [AppConfigModule],
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
