import { PATH_METADATA } from '@nestjs/common/constants';
import { UnauthorizedException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../../audit/audit.service';
import type { AuthenticatedRequest } from '../guards/auth.guard';
import { Role } from '../roles';
import type { SessionRepository } from '../session.repository';
import { ALLOW_WITHOUT_SECOND_FACTOR_KEY } from './staff-gate.guard';
import { STEP_UP_REQUIRED_KEY } from './step-up.guard';
import { TotpController } from './totp.controller';
import type { TotpService } from './totp.service';

/**
 * The gate is deny-by-default: the flag belongs to a route, never to the class,
 * so a route added later is closed until somebody names it here.
 */

const OPEN_ROUTES = ['status', 'enroll', 'confirm', 'stepup', 'startRotation', 'confirmRotation'];

/** The six paths, in the order they are declared. Rotation has no disable form. */
const ROUTE_PATHS = ['status', 'enroll', 'confirm', 'stepup', 'rotate/start', 'rotate/confirm'];

const USER_ID = '6b1f2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d';
const SESSION_ID = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
const RECOVERY_CODE = 'AAAAA-BBBBB';

/** What the guard reads: the flag set on that handler, if any. */
const flagOn = (target: object | undefined): unknown =>
  target === undefined ? undefined : Reflect.getMetadata(ALLOW_WITHOUT_SECOND_FACTOR_KEY, target);

describe('TotpController second-factor gate', () => {
  const proto = TotpController.prototype as unknown as Record<string, object | undefined>;
  const handlerOf = (name: string): object | undefined => proto[name];
  const metadataOf = (key: string, name: string): unknown => {
    const handler = handlerOf(name);

    return handler === undefined ? undefined : Reflect.getMetadata(key, handler);
  };

  it('opens the six second-factor routes and nothing else', () => {
    expect(flagOn(TotpController)).toBeUndefined();

    for (const route of OPEN_ROUTES) {
      expect(flagOn(proto[route])).toBe(true);
    }

    const open = Object.getOwnPropertyNames(proto).filter((name) => flagOn(proto[name]) === true);

    expect(open.sort()).toEqual([...OPEN_ROUTES].sort());
  });

  /**
   * A new handler changes this list. That is the point: there is no route that
   * deletes, disables or resets a factor without a confirm step, and adding one
   * cannot go unnoticed.
   */
  it('exposes exactly six handlers with the six expected paths', () => {
    const routes = Object.getOwnPropertyNames(proto)
      .filter((name) => name !== 'constructor')
      .map((name) => ({ name, path: metadataOf(PATH_METADATA, name) }))
      .filter((route) => typeof route.path === 'string');

    expect(routes.map((route) => route.name).sort()).toEqual([...OPEN_ROUTES].sort());
    expect(routes.map((route) => route.path).sort()).toEqual([...ROUTE_PATHS].sort());
  });

  /** Both rotation routes change the factor, so both need a fresh proof. */
  it('requires a step-up on both rotation handlers only', () => {
    for (const route of ['startRotation', 'confirmRotation']) {
      expect(metadataOf(STEP_UP_REQUIRED_KEY, route)).toBe(true);
    }

    for (const route of ['status', 'enroll', 'confirm', 'stepup']) {
      expect(metadataOf(STEP_UP_REQUIRED_KEY, route)).toBeUndefined();
    }
  });
});

describe('TotpController rotation', () => {
  function createHarness(outcome: 'rotated' | 'rejected' = 'rotated') {
    const totp = {
      confirmRotation: jest
        .fn()
        .mockResolvedValue(
          outcome === 'rotated'
            ? { outcome: 'rotated', recoveryCodes: [RECOVERY_CODE] }
            : { outcome: 'rejected' },
        ),
    };
    const sessions = { revokeOtherUserSessions: jest.fn().mockResolvedValue(undefined) };
    const audit = { record: jest.fn().mockResolvedValue(undefined) };
    const logger = { warn: jest.fn() };
    const controller = new TotpController(
      totp as unknown as TotpService,
      sessions as unknown as SessionRepository,
      audit as unknown as AuditService,
      logger as unknown as PinoLogger,
    );
    const request = {
      auth: { userId: USER_ID, sessionId: SESSION_ID, role: Role.ADMIN },
    } as unknown as AuthenticatedRequest;

    return { controller, totp, sessions, audit, request };
  }

  it('keeps the calling session, revokes every other one and audits counts only', async () => {
    const { controller, sessions, audit, request } = createHarness();

    const result = await controller.confirmRotation({ code: '123456' }, request);

    expect(result).toEqual({ recoveryCodes: [RECOVERY_CODE] });
    // The current session is the exception, so its step-up stamp survives.
    expect(sessions.revokeOtherUserSessions).toHaveBeenCalledWith(
      USER_ID,
      SESSION_ID,
      'totp_rotated',
      expect.any(Date),
    );
    expect(audit.record).toHaveBeenCalledWith({
      action: 'totp.rotated',
      actorId: USER_ID,
      targetType: 'user',
      targetId: USER_ID,
      metadata: { recoveryCodesIssued: 1 },
    });

    const trail = JSON.stringify(audit.record.mock.calls);

    expect(trail).not.toContain('123456');
    expect(trail).not.toContain(RECOVERY_CODE);
  });

  it('touches neither sessions nor the trail when the code is refused', async () => {
    const { controller, sessions, audit, request } = createHarness('rejected');

    await expect(controller.confirmRotation({ code: '123456' }, request)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(sessions.revokeOtherUserSessions).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('refuses a malformed body before verifying it', async () => {
    const { controller, totp, request } = createHarness();

    await expect(
      controller.confirmRotation({ code: 'x'.repeat(21) }, request),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(totp.confirmRotation).not.toHaveBeenCalled();
  });
});
