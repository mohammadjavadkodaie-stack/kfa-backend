import { ALLOW_WITHOUT_SECOND_FACTOR_KEY } from './staff-gate.guard';
import { TotpController } from './totp.controller';

/**
 * The gate is deny-by-default: the flag belongs to a route, never to the class,
 * so a route added later is closed until somebody names it here.
 */

const OPEN_ROUTES = ['status', 'enroll', 'confirm', 'stepup'];

/** What the guard reads: the flag set on that handler, if any. */
const flagOn = (target: object | undefined): unknown =>
  target === undefined ? undefined : Reflect.getMetadata(ALLOW_WITHOUT_SECOND_FACTOR_KEY, target);

describe('TotpController second-factor gate', () => {
  const proto = TotpController.prototype as unknown as Record<string, object>;

  it('opens the four second-factor routes and nothing else', () => {
    expect(flagOn(TotpController)).toBeUndefined();

    for (const route of OPEN_ROUTES) {
      expect(flagOn(proto[route])).toBe(true);
    }

    const open = Object.getOwnPropertyNames(proto).filter((name) => flagOn(proto[name]) === true);

    expect(open.sort()).toEqual([...OPEN_ROUTES].sort());
  });
});
