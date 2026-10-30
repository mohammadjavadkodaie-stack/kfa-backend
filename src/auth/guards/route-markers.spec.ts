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
 */

const SRC_DIR = join(__dirname, '..', '..');

const MARKER_KEYS = [IS_PUBLIC_KEY, ROLES_KEY, REQUIRES_IDENTITY_VERIFIER_KEY, AUTHENTICATED_KEY];

type ControllerClass = new (...args: never[]) => object;

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

function hasMarker(handler: object, controller: object): boolean {
  return MARKER_KEYS.some(
    (key) =>
      Reflect.getMetadata(key, handler) !== undefined ||
      Reflect.getMetadata(key, controller) !== undefined,
  );
}

function offenders(): string[] {
  const found: string[] = [];
  let handlers = 0;

  for (const file of controllerFiles(SRC_DIR)) {
    const loaded: Record<string, unknown> = require(file) as Record<string, unknown>;

    for (const exported of Object.values(loaded)) {
      if (!isController(exported)) continue;

      const prototype = exported.prototype as Record<string, unknown>;

      for (const name of Object.getOwnPropertyNames(prototype)) {
        const handler = prototype[name];

        if (typeof handler !== 'function') continue;
        if (Reflect.getMetadata(METHOD_METADATA, handler) === undefined) continue;

        handlers += 1;

        if (!hasMarker(handler, exported)) found.push(`${exported.name}.${name}`);
      }
    }
  }

  // A scan that finds nothing must not pass silently.
  if (handlers === 0) throw new Error('no controller handlers were found');

  return found;
}

describe('route markers', () => {
  it('marks every non-public handler', () => {
    expect(offenders()).toEqual([]);
  });
});
