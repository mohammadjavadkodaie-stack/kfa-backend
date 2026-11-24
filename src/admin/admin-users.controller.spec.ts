import { BadRequestException } from '@nestjs/common';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { Role } from '../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import { AdminUsersController } from './admin-users.controller';
import {
  MAX_MODERATION_REASON_LENGTH,
  MIN_MODERATION_REASON_LENGTH,
  parseModerationReason,
} from './admin-users.dto';
import type { AdminUsersService } from './admin-users.service';

/**
 * The moderation routes at the controller seam: what the decorators declare,
 * and what the controller hands the service.
 *
 * The guards themselves are global and covered by the route-marker sweep; the
 * point here is that block/unblock cannot lose their role or step-up marker,
 * that the required `reason` is the only input the body may carry, and that an
 * invalid one is refused before any service call - so nothing is blocked,
 * unblocked or recorded. The reason reaches the service and appears nowhere in
 * what the route returns.
 */

const ACTOR_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const REQUEST_ID = 'req-moderation';
/** Long enough to pass, short enough to read; never echoed back. */
const REASON = 'repeated abusive messages';

const request = {
  auth: { userId: ACTOR_ID, role: Role.ADMIN },
  id: REQUEST_ID,
} as unknown as AuthenticatedRequest;

const ROUTES = ['block', 'unblock'] as const;

function createController() {
  const users = {
    block: jest.fn(async () => undefined),
    unblock: jest.fn(async () => undefined),
  };
  const controller = new AdminUsersController(users as unknown as AdminUsersService);

  return { controller, users };
}

/** The thrown error, for a call whose only correct outcome is a refusal. */
function refusalOf(run: () => unknown): BadRequestException {
  try {
    run();
  } catch (error) {
    return error as BadRequestException;
  }

  throw new Error('the call was expected to be refused');
}

describe('AdminUsersController moderation routes', () => {
  it.each(ROUTES)('%s is staff-only: ADMIN and OWNER, never USER or ATHLETE', (route) => {
    const handler = AdminUsersController.prototype[route];

    expect(Reflect.getMetadata(ROLES_KEY, handler)).toEqual([Role.ADMIN, Role.OWNER]);
  });

  it.each(ROUTES)('%s requires a step-up proof even with a valid reason', (route) => {
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, AdminUsersController.prototype[route])).toBe(
      true,
    );
  });

  it.each(ROUTES)(
    '%s hands the principal, the id and the trimmed reason to the service',
    async (route) => {
      const { controller, users } = createController();

      await controller[route](USER_ID, { reason: `  ${REASON}  ` }, request);

      expect(users[route]).toHaveBeenCalledWith(
        { id: ACTOR_ID, role: Role.ADMIN },
        USER_ID,
        REQUEST_ID,
        REASON,
      );
    },
  );

  it.each(ROUTES)('%s returns no body, so the reason cannot be echoed', async (route) => {
    const { controller } = createController();

    await expect(controller[route](USER_ID, { reason: REASON }, request)).resolves.toBeUndefined();
  });
});

/** The body gate on its own: every refusal is the same generic 400. */
describe('moderation reason body', () => {
  const INVALID_BODIES: ReadonlyArray<readonly [string, unknown]> = [
    ['a missing body', undefined],
    ['a null body', null],
    ['an empty object', {}],
    ['a null reason', { reason: null }],
    ['a non-string reason', { reason: 42 }],
    ['an empty reason', { reason: '' }],
    ['a reason of spaces only', { reason: '     ' }],
    ['a reason shorter than the minimum', { reason: 'x'.repeat(MIN_MODERATION_REASON_LENGTH - 1) }],
    ['a reason longer than the maximum', { reason: 'x'.repeat(MAX_MODERATION_REASON_LENGTH + 1) }],
    ['markup in the reason', { reason: 'fits <b>spam</b>' }],
    ['a newline in the reason', { reason: 'line one\nline two' }],
    ['a tab in the reason', { reason: 'line one\tline two' }],
    ['a control character in the reason', { reason: 'nul\u0000byte' }],
    ['an undeclared key next to the reason', { reason: REASON, status: 'ACTIVE' }],
    ['an undeclared actor key', { reason: REASON, actorId: ACTOR_ID }],
    ['an array instead of an object', [{ reason: REASON }]],
  ];

  it.each(INVALID_BODIES)('refuses %s with the generic 400', (_label, body) => {
    const error = refusalOf(() => parseModerationReason(body));

    expect(error.getStatus()).toBe(400);
    // One message for every cause: the caller learns nothing about the schema.
    expect(error.getResponse()).toEqual({ statusCode: 400, message: 'Bad Request' });
    expect(JSON.stringify(error.getResponse())).not.toContain(REASON);
  });

  it.each(ROUTES)('%s refuses an invalid body before the service runs', async (route) => {
    for (const [, body] of INVALID_BODIES) {
      const { controller, users } = createController();

      await expect(controller[route](USER_ID, body, request)).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expect(users[route]).not.toHaveBeenCalled();
    }
  });

  it.each(ROUTES)('%s accepts a reason at either length boundary', async (route) => {
    for (const reason of [
      'x'.repeat(MIN_MODERATION_REASON_LENGTH),
      'y'.repeat(MAX_MODERATION_REASON_LENGTH),
    ]) {
      const { controller, users } = createController();

      await controller[route](USER_ID, { reason }, request);

      expect(users[route]).toHaveBeenCalledWith(
        { id: ACTOR_ID, role: Role.ADMIN },
        USER_ID,
        REQUEST_ID,
        reason,
      );
    }
  });
});
