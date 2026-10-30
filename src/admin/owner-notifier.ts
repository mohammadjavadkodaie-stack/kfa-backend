import { Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';

/** One grant, described by ids only: there is no phone number and no name to leak. */
export interface AdminGrantedNotice {
  readonly actorId: string;
  readonly targetId: string;
  readonly at: Date;
}

/** Best effort by contract: the caller decides what a failed delivery means. */
export interface OwnerNotifier {
  notifyAdminGranted(notice: AdminGrantedNotice): Promise<void>;
}

export const OWNER_NOTIFIER = Symbol('OWNER_NOTIFIER');

/**
 * Default adapter: one structured log line and nothing else. A real SMS or
 * Telegram adapter replaces this provider; the module that calls it stays the
 * same.
 */
@Injectable()
export class LogOwnerNotifier implements OwnerNotifier {
  constructor(private readonly logger: PinoLogger) {}

  async notifyAdminGranted(notice: AdminGrantedNotice): Promise<void> {
    this.logger.info(
      { actorId: notice.actorId, targetId: notice.targetId, at: notice.at.toISOString() },
      'admin granted',
    );
  }
}
