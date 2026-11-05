import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { AUTHENTICATED_KEY } from '../decorators/authenticated.decorator';
import { REQUIRES_IDENTITY_VERIFIER_KEY, ROLES_KEY } from '../decorators/roles.decorator';

/**
 * Walks the real controllers and fails on any handler that carries no marker.
 *
 * The classes are read through their decorator metadata only: nothing is
 * instantiated, so this stays a pure unit test with no DI, no database and no
 * Redis. A new controller file is picked up automatically, which is the point -
 * a forgotten decorator has to break the build, not the API.
 *
 * The second check is stricter: one marker kind, not several. A class-level
 * `@Roles` covers its handlers, so a handler-level copy of the same kind still
 * counts once, while two different kinds on one route is an ambiguity that only
 * shows up as a surprise at runtime.
 */

const SRC_DIR = join(__dirname, '..', '..');

const MARKER_KEYS = [IS_PUBLIC_KEY, ROLES_KEY, REQUIRES_IDENTITY_VERIFIER_KEY, AUTHENTICATED_KEY];

/** The kinds a non-public route picks between: exactly one of these. */
const AUTHZ_KEYS = [ROLES_KEY, REQUIRES_IDENTITY_VERIFIER_KEY, AUTHENTICATED_KEY];

type ControllerClass = new (...args: never[]) => object;

/** One handler together with the class whose metadata also applies to it. */
interface RouteHandler {
  /** `Controller.handler`, the label a failure prints. */
  readonly route: string;
  readonly handler: object;
  readonly controller: object;
}

function controllerFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = join(directory, entry.name);

    if (entry.isDirectory()) return controllerFiles(full);

    return entry.name.endsWith('.controller.ts') ? [full] : [];
  });
}

function isController(value: unknown): value is ControllerClass {
  return typeof value === 'function' && Reflect.getMetadata(PATH_METADATA, value) !== undefined;
}

function routeHandlers(): RouteHandler[] {
  const found: RouteHandler[] = [];

  for (const file of controllerFiles(SRC_DIR)) {
    const loaded: Record<string, unknown> = require(file) as Record<string, unknown>;

    for (const exported of Object.values(loaded)) {
      if (!isController(exported)) continue;

      const prototype = exported.prototype as Record<string, unknown>;

      for (const name of Object.getOwnPropertyNames(prototype)) {
        const handler = prototype[name];

        if (typeof handler !== 'function') continue;
        if (Reflect.getMetadata(METHOD_METADATA, handler) === undefined) continue;

        found.push({ route: `${exported.name}.${name}`, handler, controller: exported });
      }
    }
  }

  // A scan that finds nothing must not pass silently.
  if (found.length === 0) throw new Error('no controller handlers were found');

  return found;
}

/** A marker on the handler wins as usual; the class fills in the rest. */
function carried(route: RouteHandler, key: string): boolean {
  return (
    Reflect.getMetadata(key, route.handler) !== undefined ||
    Reflect.getMetadata(key, route.controller) !== undefined
  );
}

function hasMarker(route: RouteHandler): boolean {
  return MARKER_KEYS.some((key) => carried(route, key));
}

function offenders(routes: readonly RouteHandler[]): string[] {
  return routes.filter((route) => !hasMarker(route)).map((route) => route.route);
}

/** Non-public handlers that carry neither marker or more than one kind of it. */
function markerKindOffenders(routes: readonly RouteHandler[]): string[] {
  const found: string[] = [];

  for (const route of routes) {
    // @Public is its own contract, not one of the three kinds.
    if (carried(route, IS_PUBLIC_KEY)) continue;

    const kinds = AUTHZ_KEYS.filter((key) => carried(route, key));

    if (kinds.length !== 1) found.push(`${route.route} (${kinds.length} kinds)`);
  }

  return found;
}

describe('route markers', () => {
  it('marks every non-public handler', () => {
    expect(offenders(routeHandlers())).toEqual([]);
  });

  it('gives every non-public handler exactly one marker kind', () => {
    expect(markerKindOffenders(routeHandlers())).toEqual([]);
  });
});
