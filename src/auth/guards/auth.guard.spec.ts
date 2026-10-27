import { UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { AuthGuard } from './auth.guard';

const handler = (): void => undefined;
class TestController {}

const context = {
  getHandler: () => handler,
  getClass: () => TestController,
} as unknown as ExecutionContext;

function createReflector(isPublic: boolean | undefined): {
  reflector: Reflector;
  getAllAndOverride: jest.Mock;
} {
  const getAllAndOverride = jest.fn().mockReturnValue(isPublic);

  return { reflector: { getAllAndOverride } as unknown as Reflector, getAllAndOverride };
}

describe('AuthGuard', () => {
  it('allows routes marked with @Public()', () => {
    const { reflector } = createReflector(true);

    expect(new AuthGuard(reflector).canActivate(context)).toBe(true);
  });

  it('denies every route that is not explicitly public', () => {
    const { reflector } = createReflector(undefined);

    expect(() => new AuthGuard(reflector).canActivate(context)).toThrow(UnauthorizedException);
  });

  it('treats an explicit `false` as protected', () => {
    const { reflector } = createReflector(false);

    expect(() => new AuthGuard(reflector).canActivate(context)).toThrow(UnauthorizedException);
  });

  it('reads the metadata from both the handler and the controller', () => {
    const { reflector, getAllAndOverride } = createReflector(undefined);

    expect(() => new AuthGuard(reflector).canActivate(context)).toThrow(UnauthorizedException);
    expect(getAllAndOverride).toHaveBeenCalledWith(IS_PUBLIC_KEY, [handler, TestController]);
  });
});
