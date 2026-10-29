import type { NextFunction, Request, Response } from 'express';

/**
 * Bodies of these routes carry a secret, recovery codes or a code. Set here
 * instead of per handler so the guard refusals are not cacheable either.
 */
export function noStoreMiddleware(_request: Request, response: Response, next: NextFunction): void {
  response.setHeader('Cache-Control', 'no-store');
  next();
}
