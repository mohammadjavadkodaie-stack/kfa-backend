import { forwardRef, MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { NOTIFICATION_REPOSITORY } from './notification.repository';
import { PrismaNotificationRepository } from './prisma-notification.repository';
import { NotificationsController } from './notifications.controller';
import { NotificationsService, REVIEW_DECISION_INBOX } from './notifications.service';

@Module({
  // AuthModule supplies the one authentication check the routes need;
  // RateLimitModule the per-user counters the two routes consume.
  imports: [forwardRef(() => AuthModule), RateLimitModule],
  controllers: [NotificationsController],
  providers: [
    NotificationsService,
    { provide: NOTIFICATION_REPOSITORY, useClass: PrismaNotificationRepository },
    // The staff review module writes the inbox through this token; `useExisting`
    // keeps both bindings on the same service instance.
    { provide: REVIEW_DECISION_INBOX, useExisting: NotificationsService },
  ],
  exports: [NotificationsService, REVIEW_DECISION_INBOX, NOTIFICATION_REPOSITORY],
})
export class NotificationsModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Personal data: no proxy or browser may cache an answer.
    consumer.apply(noStoreMiddleware).forRoutes(NotificationsController);
  }
}
