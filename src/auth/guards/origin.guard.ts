import {
  ForbiddenException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { ENV } from '../../config/config.module';
import type { Env } from '../../config/env';

/**
 * Origin / CSRF check for the cookie-bearing endpoints.
 *
 * The refresh cookie is `SameSite=Strict`, which already blocks cross-site
 * sends, but that is a browser guarantee only. This guard makes the rule
 * explicit server-side:
 *
 * - `Origin` present  -> it must be one of APP_ORIGINS.
 * - `Origin` absent   -> `Sec-Fetch-Site` must not be cross-site.
 * - Both absent       -> allowed, because non-browser clients send neither.
 */

export const ORIGIN_HEADER = 'origin';
export const SEC_FETCH_SITE_HEADER = 'sec-fetch-site';

export interface OriginEvidence {
  readonly origin: string | undefined;
  readonly secFetchSite: string | undefined;
}

export function isAllowedOrigin(
  evidence: OriginEvidence,
  allowedOrigins: readonly string[],
): boolean {
  const origin = evidence.origin;
  const fetchSite = evidence.secFetchSite?.toLowerCase();

  if (fetchSite === 'cross-site') {
    return false;
  }

  if (origin === undefined || origin.length === 0) {
    return true;
  }

  return allowedOrigins.includes(origin);
}

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

@Injectable()
export class OriginCheckGuard implements CanActivate {
  private readonly allowedOrigins: readonly string[];

  constructor(@Inject(ENV) env: Pick<Env, 'APP_ORIGINS'>) {
    this.allowedOrigins = env.APP_ORIGINS;
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    const allowed = isAllowedOrigin(
      {
        origin: single(request.headers[ORIGIN_HEADER]),
        secFetchSite: single(request.headers[SEC_FETCH_SITE_HEADER]),
      },
      this.allowedOrigins,
    );

    if (!allowed) {
      // Generic: the caller learns nothing about the allowlist.
      throw new ForbiddenException();
    }

    return true;
  }
}
