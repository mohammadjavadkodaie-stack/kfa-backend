import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import { OriginCheckGuard, isAllowedOrigin } from './origin.guard';

const ALLOWED = ['https://app.example', 'https://admin.example'];

function createContext(headers: Record<string, string | string[] | undefined>): ExecutionContext {
  const request = { headers } as unknown as Request;

  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

describe('isAllowedOrigin', () => {
  it.each(ALLOWED)('allows the configured origin %s', (origin) => {
    expect(isAllowedOrigin({ origin, secFetchSite: undefined }, ALLOWED)).toBe(true);
  });

  it('rejects an origin that is not on the list', () => {
    expect(
      isAllowedOrigin({ origin: 'https://evil.example', secFetchSite: undefined }, ALLOWED),
    ).toBe(false);
  });

  it('allows a request that sends neither header (non-browser client)', () => {
    expect(isAllowedOrigin({ origin: undefined, secFetchSite: undefined }, ALLOWED)).toBe(true);
  });

  it('rejects a cross-site request even without an Origin header', () => {
    expect(isAllowedOrigin({ origin: undefined, secFetchSite: 'cross-site' }, ALLOWED)).toBe(false);
  });

  it('rejects a cross-site request that carries an allowed-looking origin', () => {
    expect(
      isAllowedOrigin({ origin: 'https://app.example', secFetchSite: 'cross-site' }, ALLOWED),
    ).toBe(false);
  });

  it('allows same-origin and user-initiated requests without an Origin', () => {
    expect(isAllowedOrigin({ origin: undefined, secFetchSite: 'same-origin' }, ALLOWED)).toBe(true);
    expect(isAllowedOrigin({ origin: undefined, secFetchSite: 'none' }, ALLOWED)).toBe(true);
  });

  it('treats Sec-Fetch-Site case-insensitively', () => {
    expect(isAllowedOrigin({ origin: undefined, secFetchSite: 'CROSS-SITE' }, ALLOWED)).toBe(false);
  });

  it('requires an exact origin match', () => {
    expect(
      isAllowedOrigin({ origin: 'https://app.example.evil', secFetchSite: undefined }, ALLOWED),
    ).toBe(false);
    expect(
      isAllowedOrigin({ origin: 'https://app.example/', secFetchSite: undefined }, ALLOWED),
    ).toBe(false);
  });
});

describe('OriginCheckGuard', () => {
  const guard = new OriginCheckGuard({ APP_ORIGINS: ALLOWED });

  it('passes an allowed browser request through', () => {
    expect(
      guard.canActivate(
        createContext({ origin: 'https://app.example', 'sec-fetch-site': 'same-site' }),
      ),
    ).toBe(true);
  });

  it('passes a request with no origin headers through', () => {
    expect(guard.canActivate(createContext({}))).toBe(true);
  });

  it('refuses a foreign origin generically', () => {
    expect(() => guard.canActivate(createContext({ origin: 'https://evil.example' }))).toThrow(
      ForbiddenException,
    );
  });

  it('refuses a cross-site request without an origin', () => {
    expect(() => guard.canActivate(createContext({ 'sec-fetch-site': 'cross-site' }))).toThrow(
      ForbiddenException,
    );
  });

  it('uses the first value of a repeated header', () => {
    expect(() =>
      guard.canActivate(createContext({ origin: ['https://evil.example', 'https://app.example'] })),
    ).toThrow(ForbiddenException);
  });
});
