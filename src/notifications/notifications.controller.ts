import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ArrayMaxSize,
  ArrayMinSize,
  Equals,
  IsArray,
  IsBoolean,
  IsOptional,
  IsUUID,
  Matches,
  ValidateIf,
} from 'class-validator';
import type { Response } from 'express';
import { Authenticated } from '../auth/decorators/authenticated.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { OriginCheckGuard } from '../auth/guards/origin.guard';
import { writeTooManyRequests, type ErrorResponseBody } from '../common/errors/error-response';
import { RateLimitService } from '../rate-limit/rate-limit.service';
import {
  MAX_MARK_READ_IDS,
  NotificationsService,
  type NotificationPage,
} from './notifications.service';

/** The same shape the client accepts for a cursor: opaque to the UI, query-only. */
const CURSOR_PATTERN = /^[A-Za-z0-9_.~=-]{1,512}$/;

/**
 * `GET /notifications?cursor=`. Everything is optional and `cursor` is the only
 * declared field, so the global pipe turns a misspelled or unknown parameter -
 * including any attempt to widen the page - into a generic 400.
 */
export class NotificationListQueryDto {
  @IsOptional()
  @Matches(CURSOR_PATTERN)
  cursor?: string;
}

/**
 * One target or the other. Each field validates only while the other is
 * absent, so `{}` fails both branches, `{ ids, all }` fails both, and the
 * service refuses whatever the pipe would still let through.
 */
export class MarkNotificationsReadDto {
  @ValidateIf((body: MarkNotificationsReadDto) => body.all === undefined)
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(MAX_MARK_READ_IDS)
  @IsUUID('all', { each: true })
  ids?: string[];

  @ValidateIf((body: MarkNotificationsReadDto) => body.ids === undefined)
  @IsBoolean()
  @Equals(true)
  all?: true;
}

/** Per-user budgets, keyed by the account and never by the address. */
export const NOTIFICATION_LIST_RATE_LIMIT_SCOPE = 'notification-list';
export const NOTIFICATION_READ_RATE_LIMIT_SCOPE = 'notification-read';

/**
 * Listing is one indexed read the page asks for on every visit, so the limit is
 * generous; marking read is rarer still. Both are well above a person clicking
 * around and both bound a script.
 */
export const NOTIFICATION_LIST_LIMITS = [{ limit: 60, windowSeconds: 60 }] as const;
export const NOTIFICATION_READ_LIMITS = [{ limit: 30, windowSeconds: 60 }] as const;

/**
 * The shared loop: the windows are checked in order and the first refusal wins,
 * so a caller that is out of budget never reaches the service. The answer goes
 * through the shared helper, so the envelope and the `Retry-After` rounding
 * match every other limited route in the API.
 */
async function consumeOrRefuse(
  rateLimit: RateLimitService,
  scope: string,
  limits: readonly { readonly limit: number; readonly windowSeconds: number }[],
  identifier: string,
  request: AuthenticatedRequest,
  response: Response,
): Promise<ErrorResponseBody | null> {
  for (const limit of limits) {
    const decision = await rateLimit.consume({ scope, identifier, ...limit });

    if (!decision.allowed)
      return writeTooManyRequests(response, request, decision.retryAfterSeconds);
  }

  return null;
}

/**
 * The caller's own notifications: `GET /notifications` and
 * `POST /notifications/read`.
 *
 * Only `@Authenticated` - every signed-in role reaches them - but neither route
 * names an owner: the account is the verified principal, so a staff member who
 * calls them reads and marks their own inbox and nobody else's.
 *
 * The read route carries `OriginCheckGuard` like every other state-changing
 * route, answers the same `{ unreadCount }` for an id that belongs to somebody
 * else as for one that does not exist, and never answers a delete. Marking read
 * is not undoable in the API: read_at only ever moves forward.
 */
@Controller('notifications')
export class NotificationsController {
  constructor(
    private readonly notifications: NotificationsService,
    private readonly rateLimit: RateLimitService,
  ) {}

  @Authenticated()
  @Get()
  async list(
    @Query() query: NotificationListQueryDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<NotificationPage | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await consumeOrRefuse(
      this.rateLimit,
      NOTIFICATION_LIST_RATE_LIMIT_SCOPE,
      NOTIFICATION_LIST_LIMITS,
      actor.id,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    return this.notifications.list(actor.id, query.cursor);
  }

  @Authenticated()
  @UseGuards(OriginCheckGuard)
  @Post('read')
  @HttpCode(HttpStatus.OK)
  async markRead(
    @Body() body: MarkNotificationsReadDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<{ unreadCount: number } | ErrorResponseBody> {
    const actor = this.actor(request);
    const refusal = await consumeOrRefuse(
      this.rateLimit,
      NOTIFICATION_READ_RATE_LIMIT_SCOPE,
      NOTIFICATION_READ_LIMITS,
      actor.id,
      request,
      response,
    );

    if (refusal !== null) return refusal;

    return this.notifications.markRead(actor.id, { ids: body.ids, all: body.all });
  }

  /** AuthGuard runs first, so a missing principal is a wiring bug, not input. */
  private actor(request: AuthenticatedRequest): { id: string } {
    const principal = request.auth;

    if (principal === undefined) throw new ForbiddenException();

    return { id: principal.userId };
  }
}
