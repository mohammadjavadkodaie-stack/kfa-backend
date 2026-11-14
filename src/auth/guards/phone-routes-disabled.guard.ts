import {
  Inject,
  Injectable,
  NotFoundException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';

/**
 * The paths of the phone/OTP identity flow: OTP start/verify, phone
 * registration and login, and phone change. The patterns are anchored so
 * `/auth/refresh` or `/auth/logout-attempt` can never match; sub-paths and a
 * trailing slash are covered, and the check runs on a lower-cased path because
 * routing itself is case-insensitive.
 */
const PHONE_AUTH_ROUTES: readonly RegExp[] = [
  /^\/auth\/otp(?:\/|$)/,
  /^\/auth\/phone-change(?:\/|$)/,
  /^\/auth\/register\/?$/,
  /^\/auth\/login\/?$/,
];

/** Pure matcher, unit-tested on its own. */
export function isPhoneAuthRoute(path: string): boolean {
  const normalised = path.toLowerCase();

  return PHONE_AUTH_ROUTES.some((route) => route.test(normalised));
}

/**
 * Answers a generic 404 for the phone/OTP routes in production.
 *
 * The phone identity flow is switched off in production: no SMS adapter is
 * configured, and the endpoints must be indistinguishable from a route that
 * does not exist. This guard is registered as the first global guard, before
 * throttling and authentication, so a disabled route leaks nothing at all. The
 * thrown `NotFoundException` is rendered by `AllExceptionsFilter` into the
 * generic error envelope.
 */
@Injectable()
export class PhoneRoutesDisabledGuard implements CanActivate {
  constructor(@Inject(ENV) private readonly env: Pick<Env, 'NODE_ENV'>) {}

  canActivate(context: ExecutionContext): boolean {
    if (this.env.NODE_ENV !== 'production') {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const path = typeof request.path === 'string' ? request.path : '';

    if (isPhoneAuthRoute(path)) {
      throw new NotFoundException();
    }

    return true;
  }
}
