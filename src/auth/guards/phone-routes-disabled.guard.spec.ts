import { NotFoundException, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import { isPhoneAuthRoute, PhoneRoutesDisabledGuard } from './phone-routes-disabled.guard';

type NodeEnv = 'development' | 'test' | 'production';

function createContext(path: string): ExecutionContext {
  const request = { path } as Request;

  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function canActivate(path: string, nodeEnv: NodeEnv): boolean {
  const guard = new PhoneRoutesDisabledGuard({ NODE_ENV: nodeEnv });

  return guard.canActivate(createContext(path));
}

function productionRefusal(path: string): NotFoundException | null {
  try {
    canActivate(path, 'production');
    return null;
  } catch (error) {
    return error instanceof NotFoundException ? error : null;
  }
}

/** Paths that must answer the generic 404 in production. */
const PHONE_ROUTES: readonly string[] = [
  '/auth/otp',
  '/auth/otp/',
  '/auth/otp/start',
  '/auth/otp/verify',
  '/auth/register',
  '/auth/register/',
  '/auth/login',
  '/auth/login/',
  '/auth/phone-change',
  '/auth/phone-change/',
  '/auth/phone-change/start',
  '/auth/phone-change/verify-new',
  '/auth/phone-change/verify-old',
  '/auth/phone-change/confirm',
];

/** Paths that must stay live in production. */
const LIVE_ROUTES: readonly string[] = [
  '/',
  '/health',
  '/auth/refresh',
  '/auth/logout',
  '/auth/logout-all',
  '/auth/sessions',
  '/auth/sessions/6f1c2f38-2f1a-4a5f-9d0a-6f2a1b3c4d5e',
  '/auth/me',
  '/auth/email/verify',
  '/auth/email/login',
  '/auth/login-attempt',
  '/auth/register-interest',
];

describe('isPhoneAuthRoute', () => {
  it('matches every phone/OTP path, in any case, with or without a trailing slash', () => {
    for (const path of PHONE_ROUTES) expect(isPhoneAuthRoute(path)).toBe(true);
    expect(isPhoneAuthRoute('/AUTH/OTP/START')).toBe(true);
    expect(isPhoneAuthRoute('/Auth/Login/')).toBe(true);
    expect(isPhoneAuthRoute('/Auth/Phone-Change/Verify-New')).toBe(true);
  });

  it('never matches a route that stays live in production', () => {
    for (const path of LIVE_ROUTES) expect(isPhoneAuthRoute(path)).toBe(false);
    expect(isPhoneAuthRoute('/auth/logout-all')).toBe(false);
    expect(isPhoneAuthRoute('/auth/login-attempt')).toBe(false);
  });
});

describe('PhoneRoutesDisabledGuard', () => {
  it('lets every route through outside production', () => {
    for (const path of [...PHONE_ROUTES, ...LIVE_ROUTES]) {
      expect(canActivate(path, 'development')).toBe(true);
      expect(canActivate(path, 'test')).toBe(true);
    }
  });

  it('answers a generic 404 for the phone/OTP routes in production', () => {
    for (const path of PHONE_ROUTES) {
      const error = productionRefusal(path);

      expect(error).toBeInstanceOf(NotFoundException);
      expect(error?.getStatus()).toBe(404);
      expect(error?.message).toBe('Not Found');
    }
  });

  it('keeps every other route live in production', () => {
    for (const path of LIVE_ROUTES) expect(canActivate(path, 'production')).toBe(true);
  });
});
